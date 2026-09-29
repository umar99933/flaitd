"""Post-hoc, descriptive follow-up to the budget sweep (saved scores only; no retraining, no setting changed).

1. 95% bootstrap CIs for test insiders found and session precision at B in CI_BUDGETS, resampling the
   test insiders with replacement (1,000 resamples, benign sessions fixed), pooled over seeds: in each
   replicate the metric is computed per seed with the same insider resample and averaged over seeds.
   Paired differences FLAITD - AND, FLAITD - Mean, FLAITD - I-only use the same replicates.
   A resampled insider carries its detection indicator and its alerted malicious sessions (owner-credited,
   so scenario-3 sessions under a supervisor's account count for the insider); false positives
   (alerted benign sessions) are fixed.
2. User-level precision at every sweep budget: insiders detected / (insiders detected + benign users
   alerted), with the definitions of metrics.user_metrics.
3. The FLAITD score ceiling: max risk, share of validation / test sessions at it, malicious among them.

Writes results/<run>/extra/budget_ci.json and prints markdown tables.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from budget_sweep import BUDGETS, METHODS, and_quantile  # noqa: E402
from flaitd.config import load_config  # noqa: E402
from flaitd.metrics import budget_threshold, evaluate  # noqa: E402
from flaitd.pipeline import Ctx  # noqa: E402

CI_BUDGETS = [1, 3, 10, 30]
PAIRS = [("FLAITD", "AND"), ("FLAITD", "Mean"), ("FLAITD", "I-only")]
N_BOOT = 1000


def alerts_for(z, mu, va, te, nd, b):
    nI, nG, risk = z["nI"], z["nG"], z["risk"]
    sm = np.minimum(mu["p_lstm"], np.nan_to_num(mu["s_iforest"], nan=0.0))
    scores = {"FLAITD": risk, "I-only": nI, "G-only": nG, "Mean": (nI + nG) / 2, "MUEBA": sm}
    a = {m: sc[te] >= budget_threshold(sc[va], nd, b) for m, sc in scores.items()}
    q = and_quantile(nI, nG, va, b * nd)
    a["AND"] = (nI[te] >= q) & (nG[te] >= q)
    a["MUEBA+FLAITD"] = ((sm[te] >= budget_threshold(sm[va], nd, b / 2))
                         | (risk[te] >= budget_threshold(risk[va], nd, b / 2)))
    return a


def ci(x):
    return [float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    rdir = Path(cfg["results_dir"])
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    ctx = Ctx(df, cfg)
    va, te, nd = ctx.val, ctx.test, ctx.n_val_days
    y, own = ctx.yt, ctx.tdf["owner"].to_numpy()
    insiders = np.array(sorted(set(own[y == 1])))
    idx = {u: i for i, u in enumerate(insiders)}
    mal_ins = np.array([idx.get(o, -1) for o in own])            # insider index of each malicious test session
    rng = np.random.default_rng(0)
    C = rng.multinomial(len(insiders), np.full(len(insiders), 1 / len(insiders)), size=N_BOOT).astype(float)

    seeds = cfg["seeds"]
    per = {b: {m: {"found": [], "prec": []} for m in METHODS} for b in BUDGETS}   # per-seed replicate arrays
    point = {b: {m: [] for m in METHODS} for b in BUDGETS}
    ceiling = {}
    for s in seeds:
        z = np.load(rdir / f"seed_{s}" / "fused_full.npz", allow_pickle=True)
        mu = np.load(rdir / f"seed_{s}" / "mueba.npz", allow_pickle=True)
        r = z["risk"]; mx = float(r.max()); at = r >= mx - 1e-9
        ceiling[str(s)] = {"max_risk": mx,
                           "val_at_max": int(at[va].sum()), "val_share": float(at[va].mean()),
                           "val_malicious_at_max": int(df["mal"].to_numpy()[va & at].sum()),
                           "test_at_max": int(at[te].sum()), "test_share": float(at[te].mean()),
                           "test_malicious_at_max": int(y[at[te]].sum())}
        for b in BUDGETS:
            for m, a in alerts_for(z, mu, va, te, nd, b).items():
                ev = evaluate(ctx.tdf, y, alert=a)
                point[b][m].append({"insiders": ev["insiders_detected"], "precision": ev["precision"],
                                    "benign_users_alerted": ev["benign_users_alerted"],
                                    "user_precision": ev["insiders_detected"] / max(ev["insiders_detected"] + ev["benign_users_alerted"], 1),
                                    "alerts": ev["alerts"]})
                if b in CI_BUDGETS:
                    hit = a & (y == 1)
                    det = np.zeros(len(insiders)); np.maximum.at(det, mal_ins[hit], 1)
                    tp = np.bincount(mal_ins[hit], minlength=len(insiders)).astype(float)
                    fp = float((a & (y == 0)).sum())
                    TP = C @ tp
                    per[b][m]["found"].append(C @ det)
                    per[b][m]["prec"].append(TP / np.maximum(TP + fp, 1))

    out = {"n_test_insiders": int(len(insiders)), "n_boot": N_BOOT, "ceiling": ceiling, "ci": {}, "diff": {}, "user_level": {}}
    for b in CI_BUDGETS:
        rep = {m: {k: np.mean(v, axis=0) for k, v in d.items()} for m, d in per[b].items()}
        out["ci"][str(b)] = {m: {"insiders": float(np.mean([p["insiders"] for p in point[b][m]])),
                                 "insiders_ci": ci(rep[m]["found"]),
                                 "precision": float(np.mean([p["precision"] for p in point[b][m]])),
                                 "precision_ci": ci(rep[m]["prec"])} for m in METHODS}
        out["diff"][str(b)] = {}
        for a_, b_ in PAIRS:
            dfnd = rep[a_]["found"] - rep[b_]["found"]; dp = rep[a_]["prec"] - rep[b_]["prec"]
            pf = np.mean([p["insiders"] for p in point[b][a_]]) - np.mean([p["insiders"] for p in point[b][b_]])
            pp = np.mean([p["precision"] for p in point[b][a_]]) - np.mean([p["precision"] for p in point[b][b_]])
            lf, lp = ci(dfnd), ci(dp)
            out["diff"][str(b)][f"{a_} - {b_}"] = {
                "insiders": float(pf), "insiders_ci": lf, "insiders_excludes_0": bool(lf[0] > 0 or lf[1] < 0),
                "precision": float(pp), "precision_ci": lp, "precision_excludes_0": bool(lp[0] > 0 or lp[1] < 0)}
    for b in BUDGETS:
        out["user_level"][str(b)] = {m: {k: float(np.mean([p[k] for p in point[b][m]]))
                                         for k in ["user_precision", "insiders", "benign_users_alerted"]} for m in METHODS}
    (rdir / "extra").mkdir(exist_ok=True)
    json.dump(out, open(rdir / "extra" / "budget_ci.json", "w"), indent=1)

    print("## CIs\n| B | Method | Insiders [95% CI] | Precision [95% CI] |\n|---|---|---|---|")
    for b in CI_BUDGETS:
        for m in METHODS:
            c = out["ci"][str(b)][m]
            print(f"| {b} | {m} | {c['insiders']:.1f} [{c['insiders_ci'][0]:.1f}, {c['insiders_ci'][1]:.1f}] | "
                  f"{c['precision']:.3f} [{c['precision_ci'][0]:.3f}, {c['precision_ci'][1]:.3f}] |")
    print("\n## Paired differences\n| B | Pair | Δ insiders [95% CI] | excl. 0 | Δ precision [95% CI] | excl. 0 |\n|---|---|---|---|---|---|")
    for b in CI_BUDGETS:
        for k, d in out["diff"][str(b)].items():
            print(f"| {b} | {k} | {d['insiders']:+.1f} [{d['insiders_ci'][0]:+.1f}, {d['insiders_ci'][1]:+.1f}] | {'yes' if d['insiders_excludes_0'] else 'no'} | "
                  f"{d['precision']:+.3f} [{d['precision_ci'][0]:+.3f}, {d['precision_ci'][1]:+.3f}] | {'yes' if d['precision_excludes_0'] else 'no'} |")
    print("\n## User-level precision\n| Method | " + " | ".join(f"B={b}" for b in BUDGETS) + " |\n|---|" + "---|" * len(BUDGETS))
    for m in METHODS:
        print(f"| {m} | " + " | ".join(f"{out['user_level'][str(b)][m]['user_precision']:.3f}" for b in BUDGETS) + " |")
    print("\n## Benign users alerted\n| Method | " + " | ".join(f"B={b}" for b in BUDGETS) + " |\n|---|" + "---|" * len(BUDGETS))
    for m in METHODS:
        print(f"| {m} | " + " | ".join(f"{out['user_level'][str(b)][m]['benign_users_alerted']:.1f}" for b in BUDGETS) + " |")
    print("\n## Ceiling"); print(json.dumps(ceiling, indent=1))


if __name__ == "__main__":
    main()
