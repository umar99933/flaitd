"""Supplementary analysis (no setting changed): budget-matched union of MUEBA and FLAITD.

Each method gets `--per-day` (default 5) alerts per day, with its threshold set on the validation period
exactly as tau_B (metrics.budget_threshold); the union of the two alert sets is evaluated on the test period.
MUEBA outputs a binary AND of two parts at 0.5; its continuous score here is min(p_lstm, s_iforest), whose
threshold at 0.5 reproduces MUEBA's own alert rule. Note: MUEBA's classifier is fitted on days 1-210, which
include the validation period, so its validation threshold is set on data it was trained on.

Writes results/<run>/extra/union_budget.json and prints a summary.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flaitd.config import load_config  # noqa: E402
from flaitd.metrics import budget_threshold, evaluate  # noqa: E402
from flaitd.pipeline import Ctx  # noqa: E402

KEYS = ["precision", "recall", "f1", "insiders_detected", "benign_users_alerted", "alerts",
        "sc1_active", "sc1_detected", "sc2_active", "sc2_detected", "sc3_active", "sc3_detected"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--per-day", type=float, default=5)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    ctx = Ctx(df, cfg)
    va, te, B = ctx.val, ctx.test, args.per_day
    out = {"per_day_each": B, "mueba_score": "min(p_lstm, s_iforest)", "seeds": {}}
    for s in cfg["seeds"]:
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        fz = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        sm = np.minimum(mu["p_lstm"], np.nan_to_num(mu["s_iforest"], nan=0.0))
        tm = budget_threshold(sm[va], ctx.n_val_days, B)
        tf = budget_threshold(fz["risk"][va], ctx.n_val_days, B)
        a_m, a_f = sm[te] >= tm, fz["risk"][te] >= tf
        own = ctx.tdf["owner"].to_numpy(); y = ctx.yt
        fm, ff = set(own[a_m & (y == 1)]), set(own[a_f & (y == 1)])
        res = {}
        for name, a in [("MUEBA @5/day", a_m), ("FLAITD @5/day", a_f), ("Union (5 + 5)", a_m | a_f)]:
            m = evaluate(ctx.tdf, y, alert=a)
            res[name] = {k: m[k] for k in KEYS if k in m}
        res["thresholds"] = {"MUEBA_min_score": float(tm), "FLAITD_risk": float(tf)}
        res["overlap"] = {"alerts_both": int((a_m & a_f).sum()), "insiders_both": len(fm & ff),
                          "insiders_MUEBA_only": len(fm - ff), "insiders_FLAITD_only": len(ff - fm)}
        out["seeds"][str(s)] = res
    (rdir / "extra").mkdir(exist_ok=True)
    json.dump(out, open(rdir / "extra" / "union_budget.json", "w"), indent=1, default=float)

    print(f"{'method':16} {'P':>13} {'R':>13} {'F1':>13} {'insiders':>9} {'sc1':>5} {'sc2':>5} {'sc3':>5} {'alerts':>7} {'benign':>7}")
    for name in ["MUEBA @5/day", "FLAITD @5/day", "Union (5 + 5)"]:
        g = lambda k: [out["seeds"][s][name][k] for s in out["seeds"]]
        f = lambda k: f"{np.mean(g(k)):.3f}±{np.std(g(k)):.3f}"
        print(f"{name:16} {f('precision'):>13} {f('recall'):>13} {f('f1'):>13} {np.mean(g('insiders_detected')):9.1f}"
              f" {np.mean(g('sc1_detected')):5.1f} {np.mean(g('sc2_detected')):5.1f} {np.mean(g('sc3_detected')):5.1f}"
              f" {np.mean(g('alerts')):7.0f} {np.mean(g('benign_users_alerted')):7.1f}")
    for k in ["alerts_both", "insiders_both", "insiders_MUEBA_only", "insiders_FLAITD_only"]:
        print(k, np.mean([out["seeds"][s]["overlap"][k] for s in out["seeds"]]))
    print("thresholds", {s: out["seeds"][s]["thresholds"] for s in out["seeds"]})
    print("insiders std union", np.std([out["seeds"][s]["Union (5 + 5)"]["insiders_detected"] for s in out["seeds"]]))


if __name__ == "__main__":
    main()
