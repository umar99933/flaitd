"""Explanations (Section VI-F): case studies and the deletion test, on seed 0."""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .features import feature_list, matrix
from .fuzzy import FuzzyFusion, ecdf_normaliser
from .group import assign_groups, forest_score, make_forest, pool_index
from .individual import rescore_individual
from .log import log


def _shap_group(forest, x):
    """TreeSHAP contributions for one session; negative values push towards 'anomalous' (shorter paths)."""
    try:
        import shap
        return shap.TreeExplainer(forest).shap_values(x.reshape(1, -1))[0]
    except Exception as e:  # shap missing or incompatible: report nothing rather than something wrong
        log(f"explain: SHAP unavailable ({e.__class__.__name__}); group attributions skipped")
        return None


def run_explain(df, cfg, seed=0):
    rdir = Path(cfg["results_dir"]) / f"seed_{seed}"
    out = Path(cfg["results_dir"]) / "explanations"; out.mkdir(parents=True, exist_ok=True)
    feats = feature_list(cfg)
    I = np.load(rdir / "individual_full.npz", allow_pickle=True)
    G = np.load(rdir / "group_full.npz", allow_pickle=True)
    Fz = np.load(rdir / "fused_full.npz", allow_pickle=True)
    params = json.loads(str(Fz["params"]))
    ff = FuzzyFusion.from_cfg(cfg["fuzzy"], **params)
    val = (df["period"] == "val").to_numpy(); test = (df["period"] == "test").to_numpy()
    nIf, nGf = ecdf_normaliser(I["score"][val]), ecdf_normaliser(G["score"][val])
    risk, tau = Fz["risk"], float(Fz["tau"])
    tp = np.flatnonzero(test & (risk >= tau) & (df["mal"].to_numpy() == 1))
    log(f"explain: {len(tp)} true-positive alerts in test")
    if len(tp) == 0:
        json.dump({"note": "no true-positive alerts"}, open(out / "deletion_test.json", "w"))
        return

    a = assign_groups(cfg, df, static=cfg["group"]["static_roles"], fallback=cfg["group"]["fallback"])
    months = sorted(df["month"].unique())
    Xraw = matrix(df, feats).astype(np.float64)
    gkey = G["gkey"]
    forests = {}

    def forest_for(i):
        k = (gkey[i], df["month"].iat[i])
        if k not in forests:
            pidx, _ = pool_index(df, a, k[0], k[1], months, cfg["group"])
            pidx = pidx if len(pidx) >= 2 else np.flatnonzero((gkey == k[0]) & (df["month"] == k[1]).to_numpy())
            forests[k] = make_forest(cfg["group"], seed, len(pidx)).fit(Xraw[pidx])
        return forests[k]

    # user training medians in raw feature space (replacement values for the deletion test)
    trn = (df["period"] == "train").to_numpy() & (df["mal"] == 0).to_numpy()
    raw = df[feats].astype(float)
    med = raw[trn].groupby(df.loc[trn, "user"]).median()
    glob_med = raw[trn].median()

    rng = np.random.default_rng(seed)
    cases, dele = [], []
    order = tp[np.argsort(-risk[tp])]
    by_scen = {}
    for i in order:
        by_scen.setdefault(int(df["owner_scenario"].iat[i]), []).append(i)
    picked = []
    while len(picked) < min(cfg["explain"]["max_cases"], len(order)):
        for sc in sorted(by_scen):
            if by_scen[sc]:
                picked.append(by_scen[sc].pop(0))
        if not any(by_scen.values()):
            break

    for i in order[:500]:
        sh_I = I["shares"][i].astype(float)
        forest = forest_for(i)
        sv = _shap_group(forest, Xraw[i])
        sh_G = np.zeros(len(feats))
        if sv is not None:
            neg = np.clip(-np.asarray(sv, float), 0, None)
            sh_G = neg / neg.sum() if neg.sum() > 0 else neg
        comb = sh_I + sh_G
        top3 = np.argsort(-comb)[:3]

        def rescored(cols):
            u = df["user"].iat[i]
            rep = med.loc[u] if u in med.index else glob_med
            x = raw.iloc[i].copy()
            for c in cols:
                x[feats[c]] = rep[feats[c]]
            xm = matrix(pd.DataFrame([x]), feats)
            sI = rescore_individual({k: I[k] for k in ["mu", "sd", "pred", "sigma"]}, df, feats, np.array([i]), xm)
            sG = forest_score(forest, xm.astype(np.float64))
            return float(ff.risk(nIf(sI), nGf(sG))[0])

        r_top = rescored(top3)
        r_rand = np.mean([rescored(rng.choice(len(feats), 3, replace=False)) for _ in range(cfg["explain"]["random_repeats"])])
        dele.append(dict(sid=int(df["sid"].iat[i]), risk=float(risk[i]), risk_top3_removed=r_top, risk_rand3_removed=float(r_rand),
                         below_tau=r_top < tau))
        if i in picked:
            nI, nG = float(nIf(I["score"][[i]])[0]), float(nGf(G["score"][[i]])[0])
            cases.append(dict(
                sid=int(df["sid"].iat[i]), user=df["user"].iat[i], insider=df["owner"].iat[i], scenario=int(df["owner_scenario"].iat[i]),
                day=int(df["day"].iat[i]), start=str(df["start"].iat[i]), risk=float(risk[i]), level=str(ff.level([risk[i]])[0]),
                s_I_percentile=nI, s_G_percentile=nG, group=str(gkey[i]),
                fired_rules=[f"I {a} & G {b} -> {o} (w={w:.2f})" for a, b, o, w in ff.trace(nI, nG)],
                top_individual=[(feats[j], round(float(sh_I[j]) * 100, 1)) for j in np.argsort(-sh_I)[:3]],
                top_group_shap=[(feats[j], round(float(sh_G[j]) * 100, 1)) for j in np.argsort(-sh_G)[:3]] if sv is not None else [],
                raw_values={f: float(raw.iloc[i][f]) for f in feats},
                attention_last10=[round(float(v), 3) for v in I["attn"][i]],
            ))
    d = pd.DataFrame(dele)
    summ = dict(n_true_positive_alerts=len(tp), n_tested=len(d),
                mean_drop_top3=float((d["risk"] - d["risk_top3_removed"]).mean()),
                mean_drop_random3=float((d["risk"] - d["risk_rand3_removed"]).mean()),
                share_below_tau_after_top3=float(d["below_tau"].mean()), tau=tau)
    d.to_csv(out / "deletion_test_sessions.csv", index=False)
    json.dump(summ, open(out / "deletion_test.json", "w"), indent=2)
    json.dump(cases, open(out / "case_studies.json", "w"), indent=2, default=str)
    log(f"explain: deletion test {summ}")
