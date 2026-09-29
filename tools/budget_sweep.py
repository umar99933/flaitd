"""Post-hoc, descriptive budget sweep (saved scores only; no retraining, no setting changed).

For B in BUDGETS alerts/day, thresholds are set on the validation period as tau_B and applied to the test
period. Methods: FLAITD, I-only, G-only, budget-matched AND (common percentile q), Mean, MUEBA (score
min(p_lstm, s_iforest), whose threshold 0.5 is MUEBA's own AND rule), and the union MUEBA+FLAITD with B/2
alerts/day each. Reports test insiders found (of 61), precision and test alerts per day; mean over seeds.
MUEBA's validation scores are in-sample for its classifier (fitted on days 1-210).

Writes results/<run>/extra/budget_sweep.json, prints a markdown table, draws fig_budget_sweep.png.
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

BUDGETS = [1, 2, 3, 5, 10, 15, 20, 30, 50]
METHODS = ["FLAITD", "I-only", "G-only", "AND", "Mean", "MUEBA", "MUEBA+FLAITD"]


def and_quantile(nI, nG, val, target):
    lo, hi = 0.0, 1.0
    for _ in range(40):
        q = (lo + hi) / 2
        if ((nI[val] >= q) & (nG[val] >= q)).sum() > target:
            lo = q
        else:
            hi = q
    return hi


def plot(res, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, muted, grid = "#0b0b0b", "#52514e", "#e4e3df"
    colors = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
    markers = ["o", "s", "^", "D", "v", "P", "X"]
    styles = ["-", "--", ":", "-.", (0, (5, 1)), "-", "--"]
    plt.rcParams.update({"font.size": 7, "font.family": "DejaVu Sans", "axes.edgecolor": muted,
                         "axes.labelcolor": ink, "xtick.color": muted, "ytick.color": muted})
    fig, axes = plt.subplots(2, 1, figsize=(3.5, 4.6), sharex=True, constrained_layout=True)
    for ax, key, ylab in [(axes[0], "insiders", "Test insiders found (of 61)"),
                          (axes[1], "precision", "Precision (test sessions)")]:
        for i, m in enumerate(METHODS):
            y = [res[m][str(b)][key] for b in BUDGETS]
            ax.plot(BUDGETS, y, color=colors[i], marker=markers[i], ls=styles[i], lw=1.4, ms=3.6,
                    mec="#fcfcfb", mew=0.5, label=m)
        ax.axvline(10, color=muted, lw=0.7, ls=(0, (2, 2)))
        ax.set_xscale("log"); ax.set_ylabel(ylab)
        ax.grid(True, color=grid, lw=0.5); ax.set_axisbelow(True)
        for s in ["top", "right"]:
            ax.spines[s].set_visible(False)
        ax.set_facecolor("#fcfcfb")
    axes[0].set_ylim(0, 61); axes[0].axhline(61, color=muted, lw=0.5)
    axes[0].text(10.5, 2, "B = 10", color=muted, fontsize=6)
    axes[1].set_xlabel("Alert budget B (alerts per day, set on validation)")
    axes[1].set_xticks(BUDGETS); axes[1].set_xticklabels([str(b) for b in BUDGETS])
    axes[1].minorticks_off(); axes[0].minorticks_off()
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="outside upper center", ncol=4, frameon=False, fontsize=6, handlelength=2.4,
               columnspacing=0.9)
    fig.patch.set_facecolor("#fcfcfb")
    fig.savefig(path, dpi=300)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    ctx = Ctx(df, cfg)
    va, te, nd = ctx.val, ctx.test, ctx.n_val_days
    ntd = df.loc[te, "day"].nunique()
    raw = {m: {str(b): [] for b in BUDGETS} for m in METHODS}
    for s in cfg["seeds"]:
        z = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        nI, nG, risk = z["nI"], z["nG"], z["risk"]
        sm = np.minimum(mu["p_lstm"], np.nan_to_num(mu["s_iforest"], nan=0.0))
        scores = {"FLAITD": risk, "I-only": nI, "G-only": nG, "Mean": (nI + nG) / 2, "MUEBA": sm}
        for b in BUDGETS:
            alerts = {m: sc[te] >= budget_threshold(sc[va], nd, b) for m, sc in scores.items()}
            q = and_quantile(nI, nG, va, b * nd)
            alerts["AND"] = (nI[te] >= q) & (nG[te] >= q)
            alerts["MUEBA+FLAITD"] = ((sm[te] >= budget_threshold(sm[va], nd, b / 2))
                                      | (risk[te] >= budget_threshold(risk[va], nd, b / 2)))
            for m in METHODS:
                r = evaluate(ctx.tdf, ctx.yt, alert=alerts[m])
                raw[m][str(b)].append({"insiders": r["insiders_detected"], "precision": r["precision"],
                                       "alerts_per_day": r["alerts"] / ntd})
    res = {m: {b: {k: float(np.mean([x[k] for x in v])) for k in v[0]} | {"insiders_std": float(np.std([x["insiders"] for x in v]))}
               for b, v in d.items()} for m, d in raw.items()}
    (rdir / "extra").mkdir(exist_ok=True)
    json.dump({"budgets": BUDGETS, "mean_over_seeds": res, "per_seed": raw}, open(rdir / "extra" / "budget_sweep.json", "w"), indent=1)
    plot(res, rdir / "extra" / "fig_budget_sweep.png")
    for key, fmt in [("insiders", "{:.1f}"), ("precision", "{:.3f}"), ("alerts_per_day", "{:.1f}")]:
        print(f"\n{key}\n| Method | " + " | ".join(f"B={b}" for b in BUDGETS) + " |\n|---|" + "---|" * len(BUDGETS))
        for m in METHODS:
            print(f"| {m} | " + " | ".join(fmt.format(res[m][str(b)][key]) for b in BUDGETS) + " |")
    print("\nmax insiders std:", max(res[m][str(b)]["insiders_std"] for m in METHODS for b in BUDGETS))


if __name__ == "__main__":
    main()
