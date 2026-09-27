"""Post-hoc analyses added after the analysis freeze (saved scores only; no retraining, no setting changed).

1. Fuzzy-MUEBA: MUEBA's two part scores (p_lstm, s_iforest) are ECDF-normalised on the validation period,
   fused with the same Mamdani system (breakpoints chosen on validation PR-AUC from the same grid), and
   thresholded at tau_B for B alerts/day; compared with MUEBA's own AND rule (both parts > 0.5).
   Caveat: MUEBA's classifier is fitted on days 1-210, so its validation scores are in-sample; the ECDF,
   the breakpoint choice and tau_B therefore rest on data the classifier was trained on.
2. Calibration of FLAITD's risk levels: share of malicious sessions per level (VL/L/M/H/VH) on the
   validation and test periods, with each seed's own breakpoints.

Writes results/<run>/extra/posthoc.json and prints a summary.
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
from flaitd.metrics import evaluate  # noqa: E402
from flaitd.pipeline import Ctx  # noqa: E402

KEYS = ["pr_auc", "roc_auc", "precision", "recall", "f1", "insiders_detected", "benign_users_alerted",
        "alerts", "sc1_detected", "sc2_detected", "sc3_detected"]
LEVELS = ["VL", "L", "M", "H", "VH"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    ctx = Ctx(df, cfg)
    y_all = df["mal"].to_numpy()
    out = {"1_fuzzy_mueba": {}, "2_calibration": {}}

    for s in cfg["seeds"]:
        # ---- 1. Fuzzy-MUEBA
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        p = np.asarray(mu["p_lstm"], float)
        g = np.nan_to_num(np.asarray(mu["s_iforest"], float), nan=0.5)
        nP, nG = ctx.normalise(p, "ecdf"), ctx.normalise(g, "ecdf")
        params, how = ctx.tune_fuzzy(nP, nG)
        risk, _ = ctx.fuzzy(nP, nG, params)
        fz = ctx.eval_score(risk)
        andr = ctx.eval_alert(np.asarray(mu["alert"]).astype(bool))
        out["1_fuzzy_mueba"][str(s)] = {
            "Fuzzy-MUEBA": {k: fz[k] for k in KEYS if k in fz} | {"tau": fz["tau"], "breakpoints": params, "how": how},
            "MUEBA AND rule": {k: andr[k] for k in KEYS if k in andr},
        }

        # ---- 2. calibration of FLAITD levels
        z = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        ff = FuzzyFusion.from_cfg(cfg["fuzzy"], **json.loads(str(z["params"])))
        lev = np.asarray(ff.level(z["risk"]))
        cal = {}
        for period, mask in [("val", ctx.val), ("test", ctx.test)]:
            rows = {}
            for L in LEVELS:
                m = mask & (lev == L)
                rows[L] = {"sessions": int(m.sum()), "malicious": int(y_all[m].sum()),
                           "share_malicious": float(y_all[m].mean()) if m.any() else None}
            rows["all"] = {"sessions": int(mask.sum()), "malicious": int(y_all[mask].sum()),
                           "share_malicious": float(y_all[mask].mean())}
            cal[period] = rows
        out["2_calibration"][str(s)] = cal

    (rdir / "extra").mkdir(exist_ok=True)
    json.dump(out, open(rdir / "extra" / "posthoc.json", "w"), indent=1, default=float)

    # ---- summary
    f1 = out["1_fuzzy_mueba"]
    print("1. Fuzzy-MUEBA vs MUEBA AND (mean ± std over seeds)")
    for name in ["MUEBA AND rule", "Fuzzy-MUEBA"]:
        parts = []
        for k in KEYS:
            v = [f1[s][name].get(k) for s in f1]
            if any(x is None for x in v):
                parts.append(f"{k}=—")
            else:
                parts.append(f"{k}={np.mean(v):.3f}±{np.std(v):.3f}")
        print(f"  {name}: " + ", ".join(parts))
    print("  breakpoints:", {s: f1[s]["Fuzzy-MUEBA"]["breakpoints"] for s in f1},
          "tau:", [round(f1[s]["Fuzzy-MUEBA"]["tau"], 3) for s in f1])
    print("2. Calibration (mean over seeds): sessions, malicious, share")
    c = out["2_calibration"]
    for period in ["val", "test"]:
        for L in LEVELS + ["all"]:
            ses = [c[s][period][L]["sessions"] for s in c]
            mal = [c[s][period][L]["malicious"] for s in c]
            sh = [x for x in (c[s][period][L]["share_malicious"] for s in c) if x is not None]
            print(f"  {period:4} {L:3} sessions {np.mean(ses):10.1f} ± {np.std(ses):7.1f}  malicious {np.mean(mal):7.1f} ± {np.std(mal):5.1f}"
                  f"  share {np.mean(sh) if sh else float('nan'):.4f} ± {np.std(sh) if sh else float('nan'):.4f}")


if __name__ == "__main__":
    main()
