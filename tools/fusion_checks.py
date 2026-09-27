"""Supplementary checks on the finished run (no model is refitted, nothing in the main results changes).

1. Does FLAITD behave like AND at the budget in every seed?
2. How many alerts per day would a session that is extreme in only one view need to get through?
3. Exact gap between the individual branch (I-only) and FLAITD, including at equal alert volume.

Writes results/<run>/extra/fusion_checks.json and prints a summary.
Usage: python tools/fusion_checks.py [--config ...]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flaitd.config import load_config  # noqa: E402
from flaitd.fuzzy import FuzzyFusion  # noqa: E402
from flaitd.metrics import budget_threshold, point_metrics  # noqa: E402

KEYS = ["pr_auc", "roc_auc", "precision", "recall", "f1", "insiders_detected", "benign_users_alerted", "alerts"]


def topk_metrics(score, y, owner, k):
    """Precision/recall/insiders when the k highest-scoring test sessions are alerted."""
    order = np.argsort(-score, kind="stable")
    alert = np.zeros(len(score), bool); alert[order[:k]] = True
    m = point_metrics(alert, y)
    m["insiders_detected"] = len(set(owner[alert & (y == 1)]))
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    val = (df["period"] == "val").to_numpy(); te = (df["period"] == "test").to_numpy()
    n_val_days = df.loc[val, "day"].nunique(); n_test_days = df.loc[te, "day"].nunique()
    y = df.loc[te, "mal"].to_numpy(); owner = df.loc[te, "owner"].to_numpy()
    B = cfg["budget"]["alerts_per_day"]
    grid = np.linspace(0, 1, 2001)
    out = {"n_val_days": int(n_val_days), "n_test_days": int(n_test_days),
           "val_sessions_per_day": float(val.sum() / n_val_days), "seeds": {}}

    for s in cfg["seeds"]:
        z = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        params = json.loads(str(z["params"]))
        ff = FuzzyFusion.from_cfg(cfg["fuzzy"], **params)
        nI, nG, risk, tau = z["nI"], z["nG"], z["risk"], float(z["tau"])
        met = json.load(open(rdir / f"seed_{s}" / "metrics.json"))["tables"]["fusion"]
        r = {"breakpoints": params, "tau_B": tau}

        # ---- 1. behaves like AND?
        rI1 = ff.risk(np.ones_like(grid), grid)                       # other view at its maximum
        r["min_other_percentile_to_alert"] = float(grid[np.argmax(rI1 >= tau)]) if (rI1 >= tau).any() else None
        a_f = risk[te] >= tau
        q = met["AND"]["q"]
        a_and = (nI[te] >= q) & (nG[te] >= q)
        lo = np.minimum(nI[te], nG[te])
        r["test_alerts"] = int(a_f.sum())
        r["alerts_with_a_view_below_0.95"] = int((a_f & (lo < 0.95)).sum())
        r["alerts_with_a_view_below_0.90"] = int((a_f & (lo < 0.90)).sum())
        r["AND_common_percentile_q"] = float(q)
        r["jaccard_FLAITD_vs_AND_alerts"] = float((a_f & a_and).sum() / max((a_f | a_and).sum(), 1))
        r["share_FLAITD_alerts_also_AND_alerts"] = float((a_f & a_and).sum() / max(a_f.sum(), 1))
        hi = np.maximum(nI[te], nG[te])
        one = (y == 1) & (hi >= 0.99) & (lo < 0.80)
        r["malicious_one_view_extreme"] = int(one.sum())
        r["malicious_one_view_extreme_alerted"] = int((one & a_f).sum())

        # ---- 2. budget needed for one-view sessions
        vr = np.sort(risk[val])[::-1]

        def budget_for(level):             # alerts/day on validation so that tau_B <= level
            return float((vr >= level).sum() / n_val_days)

        r["budget_per_day_for_High_Low_session (r=0.50)"] = budget_for(0.5 - 1e-9)
        r["budget_per_day_for_High_Medium_session (r=0.75)"] = budget_for(0.75 - 1e-9)
        need = [budget_for(v - 1e-12) for v in risk[te][one]]
        r["budget_needed_per_one_view_malicious_session"] = sorted(round(x, 1) for x in need)

        # ---- 3. I-only vs FLAITD
        gap = {k: {"I-only": met["I-only"].get(k), "FLAITD": met["FLAITD"].get(k)} for k in KEYS}
        for k in KEYS:
            a, b = gap[k]["I-only"], gap[k]["FLAITD"]
            gap[k]["FLAITD_minus_I"] = (b - a) if a is not None and b is not None else None
        r["I_vs_FLAITD_at_own_thresholds"] = gap
        kF, kI = int(a_f.sum()), int((nI[te] >= met["I-only"]["tau"]).sum())
        r["equal_volume"] = {
            f"at_FLAITD_volume_k={kF}": {"FLAITD": topk_metrics(risk[te], y, owner, kF),
                                         "I-only": topk_metrics(nI[te], y, owner, kF)},
            f"at_I-only_volume_k={kI}": {"FLAITD": topk_metrics(risk[te], y, owner, kI),
                                         "I-only": topk_metrics(nI[te], y, owner, kI)},
        }
        out["seeds"][str(s)] = r

    (rdir / "extra").mkdir(exist_ok=True)
    json.dump(out, open(rdir / "extra" / "fusion_checks.json", "w"), indent=1, default=float)
    print(json.dumps(out, indent=1, default=float))


if __name__ == "__main__":
    main()
