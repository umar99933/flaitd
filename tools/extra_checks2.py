"""Supplementary analyses (no setting changed, no model of the main run refitted):

1. MUEBA (and FLAITD / I-only for reference) on test data restricted to insiders NOT seen in MUEBA's
   training labels (no malicious session in days 1-210). All test sessions of seen insiders are removed,
   including sessions run under their accounts and sessions they own.
2. Insider detection of the union of MUEBA and FLAITD alerts, per scenario.
3. Per-user z-score baseline: the same 14 features, standardised per user exactly as the individual
   branch (seq.per_user_standardise, clean training sessions), score = mean squared z; evaluated like
   I-only (ECDF on validation, budget threshold). Deterministic, so one run serves all seeds.
   Also reported with the 11 non-keyword features, as in Table VIII.

Writes results/<run>/extra/extra2.json and prints a summary.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flaitd import seq  # noqa: E402
from flaitd.config import load_config  # noqa: E402
from flaitd.features import feature_list, matrix  # noqa: E402
from flaitd.metrics import bootstrap_ap_diff, budget_threshold, evaluate  # noqa: E402
from flaitd.pipeline import Ctx  # noqa: E402

KEYS = ["pr_auc", "roc_auc", "precision", "recall", "f1", "insiders_active", "insiders_detected",
        "benign_users_alerted", "alerts", "sc1_active", "sc1_detected", "sc2_active", "sc2_detected",
        "sc3_active", "sc3_detected"]


def slim(m):
    return {k: m[k] for k in KEYS if k in m}


def zscore_score(df, cfg, feats):
    ic = cfg["individual"]
    X = matrix(df, feats)
    fit = (df["period"] == "train").to_numpy() & (df["mal"] == 0).to_numpy()
    Z, _, _ = seq.per_user_standardise(df, X, fit, ic["std_floor"], ic.get("min_std", 0.1))
    return (Z.astype(np.float64) ** 2).mean(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    ctx = Ctx(df, cfg)
    te = ctx.test
    tdf, yt = ctx.tdf, ctx.yt
    out = {}

    # ---------------------------------------------------------------- 1. unseen insiders only
    seen = set(df.loc[(df["mal"] == 1) & df["period"].isin(["train", "val"]), "owner"])
    keep = ~(tdf["user"].isin(seen) | tdf["owner"].isin(seen)).to_numpy()
    tsub, ysub = tdf[keep].reset_index(drop=True), yt[keep]
    r1 = {"seen_insiders": sorted(seen), "n_seen": len(seen),
          "test_sessions_kept": int(keep.sum()), "malicious_kept": int(ysub.sum()), "seeds": {}}
    for s in cfg["seeds"]:
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        fz = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        met = json.load(open(rdir / f"seed_{s}" / "metrics.json"))["tables"]["fusion"]
        a_m = np.asarray(mu["alert"])[te].astype(bool)
        risk, nI = fz["risk"][te], fz["nI"][te]
        mc = cfg["mueba"]
        r1["seeds"][str(s)] = {
            "MUEBA (reimpl.)": slim(evaluate(tsub, ysub, alert=a_m[keep])),
            "MUEBA LSTM part": slim(evaluate(tsub, ysub, score=mu["p_lstm"][te][keep], tau=mc["threshold_lstm"])),
            "FLAITD": slim(evaluate(tsub, ysub, score=risk[keep], tau=float(fz["tau"]))),
            "I-only": slim(evaluate(tsub, ysub, score=nI[keep], tau=met["I-only"]["tau"])),
            "MUEBA (all test insiders)": slim(evaluate(tdf, yt, alert=a_m)),
        }
    out["1_unseen_insiders"] = r1

    # ---------------------------------------------------------------- 2. union MUEBA | FLAITD
    r2 = {}
    for s in cfg["seeds"]:
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        fz = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        a_m = np.asarray(mu["alert"])[te].astype(bool)
        a_f = fz["risk"][te] >= float(fz["tau"])
        own = tdf["owner"].to_numpy()
        found_m, found_f = set(own[a_m & (yt == 1)]), set(own[a_f & (yt == 1)])
        r2[str(s)] = {"MUEBA": slim(evaluate(tdf, yt, alert=a_m)),
                      "FLAITD": slim(evaluate(tdf, yt, alert=a_f)),
                      "MUEBA or FLAITD": slim(evaluate(tdf, yt, alert=a_m | a_f)),
                      "insiders_both": len(found_m & found_f), "insiders_MUEBA_only": len(found_m - found_f),
                      "insiders_FLAITD_only": len(found_f - found_m)}
    out["2_union"] = r2

    # ---------------------------------------------------------------- 3. per-user z-score baseline
    r3 = {}
    for name, feats in [("14 features", feature_list(cfg)), ("11 features (no K)", feature_list(cfg, drop_keywords=True))]:
        sz = zscore_score(df, cfg, feats)
        nz = ctx.normalise(sz)
        res = ctx.eval_score(nz)
        r3[name] = slim(res) | {"tau": res["tau"]}
        if name == "14 features":
            z0 = np.load(rdir / "seed_0" / "fused_full.npz", allow_pickle=True)
            users = tdf["user"].to_numpy()
            r3["bootstrap_seed0"] = {
                "PR-AUC(I-only) - PR-AUC(z-score)": bootstrap_ap_diff(z0["nI"][te], nz[te], yt, users, n=cfg["evaluation"]["bootstrap"]),
                "PR-AUC(FLAITD) - PR-AUC(z-score)": bootstrap_ap_diff(z0["risk"][te], nz[te], yt, users, n=cfg["evaluation"]["bootstrap"]),
            }
            r3["spearman_with_I-only_seed0_test"] = float(pd.Series(nz[te]).corr(pd.Series(z0["nI"][te]), method="spearman"))
    out["3_zscore_baseline"] = r3

    (rdir / "extra").mkdir(exist_ok=True)
    json.dump(out, open(rdir / "extra" / "extra2.json", "w"), indent=1, default=float)
    print(json.dumps(out, indent=1, default=float))


if __name__ == "__main__":
    main()
