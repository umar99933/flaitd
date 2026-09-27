"""Experiment orchestration: every table of the paper is produced from here.

Each seed's branch outputs are cached under results/<run>/seed_<k>/ so an interrupted run resumes.
Nothing from the test period is used for fitting, thresholds, normalisation or fuzzy breakpoints.
"""
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupKFold

from .baselines import run_classic, run_lstm_ae
from .features import feature_list
from .fuzzy import FuzzyFusion, ecdf_normaliser, minmax_normaliser
from .group import run_group
from .individual import run_individual
from .log import log
from .metrics import budget_threshold, evaluate
from .mueba import run_mueba


# ----------------------------------------------------------------------------- caching helpers
def _cached(path, fn, keys):
    path = Path(path)
    if path.exists():
        z = np.load(path, allow_pickle=True)
        return {k: z[k] for k in z.files}
    res = fn()
    np.savez_compressed(path, **{k: np.asarray(res[k]) if not np.isscalar(res[k]) else np.array(res[k]) for k in keys if k in res})
    return {k: np.asarray(res[k]) for k in keys if k in res}


# ----------------------------------------------------------------------------- fusion helpers
class Ctx:
    """Everything needed to turn two branch scores into evaluated detectors."""

    def __init__(self, df, cfg):
        self.df, self.cfg = df, cfg
        self.val = (df["period"] == "val").to_numpy()
        self.test = (df["period"] == "test").to_numpy()
        self.n_val_days = df.loc[self.val, "day"].nunique()
        self.B = cfg["budget"]["alerts_per_day"]
        self.tdf = df.loc[self.test, ["user", "owner", "owner_scenario", "insider"]].reset_index(drop=True)
        self.yt = df.loc[self.test, "mal"].to_numpy()
        self.yv = df.loc[self.val, "mal"].to_numpy()

    def normalise(self, s, how=None):
        how = how or self.cfg["normalisation"]
        f = ecdf_normaliser(s[self.val]) if how == "ecdf" else minmax_normaliser(s[self.val])
        return f(s)

    def eval_score(self, s):
        tau = budget_threshold(s[self.val], self.n_val_days, self.B)
        r = evaluate(self.tdf, self.yt, score=s[self.test], tau=tau)
        r["tau"] = float(tau)
        return r

    def eval_alert(self, a):
        return evaluate(self.tdf, self.yt, alert=np.asarray(a)[self.test].astype(bool))

    def common_quantile(self, nI, nG, op):
        """Percentile q applied to both branches so that AND/OR raises B alerts per day on validation."""
        target = self.B * self.n_val_days
        lo, hi = 0.0, 1.0
        for _ in range(40):
            q = (lo + hi) / 2
            a = (nI[self.val] >= q) & (nG[self.val] >= q) if op == "and" else (nI[self.val] >= q) | (nG[self.val] >= q)
            if a.sum() > target:
                lo = q
            else:
                hi = q
        return hi

    def fuzzy(self, nI, nG, params=None):
        fc = self.cfg["fuzzy"]
        ff = FuzzyFusion.from_cfg(fc, **(params or {}))
        return ff.risk(nI, nG), ff

    def tune_fuzzy(self, nI, nG):
        fc = self.cfg["fuzzy"]
        default = dict(medium_peak=fc["medium_peak"], high_full=fc["high_full"])
        if not fc["tune_breakpoints"] or self.yv.sum() < self.cfg["stacking"]["min_val_positives"]:
            return default, "default (too few validation positives to tune)" if fc["tune_breakpoints"] else "default"
        best, best_ap = default, -1
        for mp in fc["medium_peak_grid"]:
            for hf in fc["high_full_grid"]:
                if not (fc["low_top"] < mp < hf <= 1):
                    continue
                r, _ = self.fuzzy(nI[self.val], nG[self.val], dict(medium_peak=mp, high_full=hf))
                ap = average_precision_score(self.yv, r)
                if ap > best_ap:
                    best, best_ap = dict(medium_peak=mp, high_full=hf), ap
        return best, f"tuned on validation (AP={best_ap:.3f})"

    def stacking(self, nI, nG, seed):
        F = np.c_[nI, nG, nI * nG]
        mv = self.cfg["stacking"]["min_val_positives"]
        if self.yv.sum() >= mv:
            m = LogisticRegression(class_weight="balanced", max_iter=1000).fit(F[self.val], self.yv)
            return m.predict_proba(F)[:, 1], "fitted on validation labels"
        # Too few validation positives: out-of-fold predictions on the test users (grouped by user).
        s = np.zeros(len(F))
        ti = np.flatnonzero(self.test); users = self.df["user"].to_numpy()[ti]
        yt = self.yt
        vpred = np.zeros(self.val.sum())
        gkf = GroupKFold(n_splits=5)
        for tr, te in gkf.split(ti, yt, users):
            if yt[tr].sum() == 0:
                continue
            m = LogisticRegression(class_weight="balanced", max_iter=1000).fit(F[ti[tr]], yt[tr])
            s[ti[te]] = m.predict_proba(F[ti[te]])[:, 1]
            vpred += m.predict_proba(F[self.val])[:, 1] / 5
        s[self.val] = vpred
        return s, "grouped 5-fold CV on test users (validation had too few positives) - optimistic reference"


def fused_detectors(ctx, sI, sG, seed, norm=None, fuzzy_params=None):
    """Return {name: metrics} for all fusion rules over one pair of branch scores, plus artefacts."""
    nI, nG = ctx.normalise(sI, norm), ctx.normalise(sG, norm)
    params, how = (fuzzy_params, "given") if fuzzy_params else ctx.tune_fuzzy(nI, nG)
    risk, ff = ctx.fuzzy(nI, nG, params)
    out = {}
    out["I-only"] = ctx.eval_score(nI)
    out["G-only"] = ctx.eval_score(nG)
    for op in ["and", "or"]:
        q = ctx.common_quantile(nI, nG, op)
        a = (nI >= q) & (nG >= q) if op == "and" else (nI >= q) | (nG >= q)
        out[op.upper()] = ctx.eval_alert(a); out[op.upper()]["q"] = q
    out["Mean"] = ctx.eval_score((nI + nG) / 2)
    out["Maximum"] = ctx.eval_score(np.maximum(nI, nG))
    out["Product"] = ctx.eval_score(nI * nG)
    st, st_how = ctx.stacking(nI, nG, seed)
    out["Stacking (LR)"] = ctx.eval_score(st); out["Stacking (LR)"]["note"] = st_how
    out["FLAITD"] = ctx.eval_score(risk)
    out["FLAITD"].update(fuzzy_params=params, fuzzy_how=how)
    art = dict(nI=nI, nG=nG, risk=risk, params=params, tau=out["FLAITD"]["tau"])
    return out, art


# ----------------------------------------------------------------------------- main experiment
def run_seed(df, cfg, seed):
    rdir = Path(cfg["results_dir"]) / f"seed_{seed}"; rdir.mkdir(parents=True, exist_ok=True)
    mfile = rdir / "metrics.json"
    if mfile.exists():
        log(f"seed {seed}: metrics cached")
        return json.load(open(mfile))
    ctx = Ctx(df, cfg)
    f14, f11 = feature_list(cfg), feature_list(cfg, drop_keywords=True)
    t = {}
    ikeys = ["score", "shares", "attn", "pred", "Z", "sigma", "mu", "sd", "train_seconds", "score_seconds"]
    gkeys = ["score", "gkey", "seconds", "n_fits", "n_transductive"]

    t0 = time.time()
    I = _cached(rdir / "individual_full.npz", lambda: run_individual(df, cfg, f14, seed), ikeys)
    G = _cached(rdir / "group_full.npz", lambda: run_group(df, cfg, f14, seed), gkeys)
    t["individual_train_s"] = float(I["train_seconds"]); t["group_s"] = float(G["seconds"])
    res = {"seed": seed, "tables": {}, "timing": t}

    # Tables IV (FLAITD part) and V
    fus, art = fused_detectors(ctx, I["score"], G["score"], seed)
    res["tables"]["fusion"] = fus
    np.savez_compressed(rdir / "fused_full.npz", nI=art["nI"], nG=art["nG"], risk=art["risk"],
                        tau=art["tau"], params=json.dumps(art["params"]))
    t_f = time.time(); ctx.fuzzy(art["nI"], art["nG"], art["params"]); t["fuzzy_all_sessions_s"] = time.time() - t_f

    # Table IV baselines
    base = {"I-only (ours)": fus["I-only"], "G-only (ours)": fus["G-only"], "FLAITD": fus["FLAITD"]}
    cl_path = rdir / "classic.npz"
    if cl_path.exists():
        z = np.load(cl_path, allow_pickle=True); classic = {k: z[k] for k in z.files}
    else:
        classic, secs = run_classic(df, cfg, f14, seed); t.update({f"{k}_s": v for k, v in secs.items()})
        np.savez_compressed(cl_path, **classic)
    for k, s in classic.items():
        base[k] = ctx.eval_score(s)
    if cfg["baselines"]["lstm_ae"]:
        ae = _cached(rdir / "lstm_ae.npz", lambda: dict(zip(["score", "seconds"], run_lstm_ae(df, cfg, f14, seed))), ["score", "seconds"])
        base["LSTM-AE"] = ctx.eval_score(ae["score"])
    if cfg["mueba"]["enabled"]:
        mu = _cached(rdir / "mueba.npz", lambda: run_mueba(df, cfg, seed), ["p_lstm", "s_iforest", "alert"])
        base["MUEBA (reimpl.)"] = ctx.eval_alert(mu["alert"])
        for nm, s, thr in [("MUEBA LSTM part", mu["p_lstm"], cfg["mueba"]["threshold_lstm"]),
                           ("MUEBA iForest part", mu["s_iforest"], cfg["mueba"]["threshold_iforest"])]:
            r = evaluate(ctx.tdf, ctx.yt, score=s[ctx.test], tau=thr)   # native threshold, as in MUEBA
            r["note"] = f"native threshold {thr}"
            base[nm] = r
    res["tables"]["main"] = base

    # Table VI ablations and Table VIII keyword test
    abl = {"Full FLAITD": fus["FLAITD"]}
    fp = art["params"]
    for a in cfg["ablations"]:
        if a == "no_attention":
            Ia = _cached(rdir / "individual_noatt.npz", lambda: run_individual(df, cfg, f14, seed, attention=False), ikeys)
            abl["Without attention (plain LSTM)"] = fused_detectors(ctx, Ia["score"], G["score"], seed, fuzzy_params=fp)[0]["FLAITD"]
        elif a == "no_clean":
            Ia = _cached(rdir / "individual_noclean.npz", lambda: run_individual(df, cfg, f14, seed, clean_train=False), ikeys)
            abl["Training data not cleaned"] = fused_detectors(ctx, Ia["score"], G["score"], seed, fuzzy_params=fp)[0]["FLAITD"]
        elif a == "static_roles":
            Ga = _cached(rdir / "group_static.npz", lambda: run_group(df, cfg, f14, seed, static=True), gkeys)
            abl["Static roles (first month only)"] = fused_detectors(ctx, I["score"], Ga["score"], seed, fuzzy_params=fp)[0]["FLAITD"]
        elif a == "no_fallback":
            Ga = _cached(rdir / "group_nofallback.npz", lambda: run_group(df, cfg, f14, seed, fallback=False), gkeys)
            abl["No small-group fallback"] = fused_detectors(ctx, I["score"], Ga["score"], seed, fuzzy_params=fp)[0]["FLAITD"]
        elif a == "eif":
            Ga = _cached(rdir / "group_eif.npz", lambda: run_group(df, cfg, f14, seed, tree_type="eif"), gkeys)
            abl["Extended Isolation Forest"] = fused_detectors(ctx, I["score"], Ga["score"], seed, fuzzy_params=fp)[0]["FLAITD"]
        elif a == "minmax":
            abl["Min-max instead of ECDF"] = fused_detectors(ctx, I["score"], G["score"], seed, norm="minmax", fuzzy_params=fp)[0]["FLAITD"]
        elif a == "no_keywords":
            Ik = _cached(rdir / "individual_nokw.npz", lambda: run_individual(df, cfg, f11, seed), ikeys)
            Gk = _cached(rdir / "group_nokw.npz", lambda: run_group(df, cfg, f11, seed), gkeys)
            fk = fused_detectors(ctx, Ik["score"], Gk["score"], seed, fuzzy_params=fp)[0]
            res["tables"]["keywords"] = {"all": {k: fus[k] for k in ["I-only", "G-only", "FLAITD"]},
                                         "no_keywords": {k: fk[k] for k in ["I-only", "G-only", "FLAITD"]}}
    res["tables"]["ablation"] = abl
    t["seed_total_s"] = time.time() - t0
    json.dump(res, open(mfile, "w"), indent=1, default=float)
    log(f"seed {seed}: done in {t['seed_total_s']:.0f}s")
    return res


def run_all(df, cfg, seeds=None):
    seeds = cfg["seeds"] if seeds is None else seeds
    return [run_seed(df, cfg, s) for s in seeds]
