"""Aggregate per-seed results into the paper's tables (markdown + CSV), bootstrap CIs and figures."""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .log import log
from .metrics import bootstrap_ap_diff, budget_threshold

MAIN_ROWS = ["OCSVM", "LOF", "iForest (pooled)", "LSTM-AE", "I-only (ours)", "G-only (ours)", "MUEBA (reimpl.)", "FLAITD"]
SUPP_ROWS = ["MUEBA LSTM part", "MUEBA iForest part"]
FUSION_ROWS = ["AND", "OR", "Mean", "Maximum", "Product", "Stacking (LR)", "FLAITD"]


def _ms(vals, nd=3):
    v = np.array([x for x in vals if x is not None and np.isfinite(x)], float)
    if len(v) == 0:
        return "—"
    return f"{v.mean():.{nd}f} ± {v.std():.{nd}f}" if len(v) > 1 else f"{v.mean():.{nd}f}"


def _cnt(vals_num, vals_den):
    n = np.array(vals_num, float); d = np.array(vals_den, float)
    return f"{n.mean():.1f}/{d.mean():.0f}" if len(n) else "—"


def _collect(results, table, row, key):
    out = []
    for r in results:
        t = r["tables"].get(table, {})
        if row in t and key in t[row]:
            out.append(t[row][key])
    return out


def _md(df):
    cols = list(df.columns)
    lines = ["| " + " | ".join([df.index.name or ""] + cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for i, r in df.iterrows():
        lines.append("| " + " | ".join([str(i)] + [str(x) for x in r.values]) + " |")
    return "\n".join(lines)


def build_tables(results):
    T = {}
    rows = []
    for m in MAIN_ROWS + SUPP_ROWS:
        rows.append(dict(Method=m, **{
            "PR-AUC": _ms(_collect(results, "main", m, "pr_auc")), "ROC-AUC": _ms(_collect(results, "main", m, "roc_auc")),
            "P@B": _ms(_collect(results, "main", m, "precision")), "R@B": _ms(_collect(results, "main", m, "recall")),
            "F1@B": _ms(_collect(results, "main", m, "f1")),
            "Insiders": _cnt(_collect(results, "main", m, "insiders_detected"), _collect(results, "main", m, "insiders_active")),
            "Benign users alerted": _ms(_collect(results, "main", m, "benign_users_alerted"), 1),
            "Alerts": _ms(_collect(results, "main", m, "alerts"), 0)}))
    T["IV_main"] = pd.DataFrame(rows).set_index("Method")
    rows = []
    for m in FUSION_ROWS:
        rows.append(dict(Fusion=m, **{
            "PR-AUC": _ms(_collect(results, "fusion", m, "pr_auc")), "P@B": _ms(_collect(results, "fusion", m, "precision")),
            "R@B": _ms(_collect(results, "fusion", m, "recall")),
            "Insiders": _cnt(_collect(results, "fusion", m, "insiders_detected"), _collect(results, "fusion", m, "insiders_active")),
            "Alerts": _ms(_collect(results, "fusion", m, "alerts"), 0)}))
    T["V_fusion"] = pd.DataFrame(rows).set_index("Fusion")
    names = list(results[0]["tables"]["ablation"].keys())
    T["VI_ablation"] = pd.DataFrame([dict(Variant=n, **{"PR-AUC": _ms(_collect(results, "ablation", n, "pr_auc")),
                                                         "R@B": _ms(_collect(results, "ablation", n, "recall"))}) for n in names]).set_index("Variant")
    scen = sorted({int(k[2]) for r in results for k in r["tables"]["fusion"]["FLAITD"] if k.startswith("sc") and k.endswith("_active")})
    rows = []
    for s in scen:
        row = {"Scenario": s, "Active": _ms(_collect(results, "fusion", "FLAITD", f"sc{s}_active"), 1)}
        for m in ["I-only", "G-only", "AND", "FLAITD"]:
            row[m] = _ms([x or 0 for x in _collect(results, "fusion", m, f"sc{s}_detected")], 1)
        rows.append(row)
    T["VII_scenario"] = pd.DataFrame(rows).set_index("Scenario")
    if "keywords" in results[0]["tables"]:
        rows = []
        for m in ["I-only", "G-only", "FLAITD"]:
            a = [r["tables"]["keywords"]["all"][m] for r in results]; b = [r["tables"]["keywords"]["no_keywords"][m] for r in results]
            rows.append(dict(Method=m, **{"PR-AUC all 14": _ms([x.get("pr_auc") for x in a]), "PR-AUC without K": _ms([x.get("pr_auc") for x in b]),
                                          "R@B all 14": _ms([x["recall"] for x in a]), "R@B without K": _ms([x["recall"] for x in b])}))
        T["VIII_keywords"] = pd.DataFrame(rows).set_index("Method")
    return T


def seed0_extras(df, cfg):
    """Bootstrap CIs, one-branch-only insiders and PR curves from the seed-0 scores."""
    rdir = Path(cfg["results_dir"]) / "seed_0"
    if not (rdir / "fused_full.npz").exists():
        return {}
    Fz = np.load(rdir / "fused_full.npz", allow_pickle=True)
    val = (df["period"] == "val").to_numpy(); test = (df["period"] == "test").to_numpy()
    y = df.loc[test, "mal"].to_numpy(); users = df.loc[test, "owner"].to_numpy()
    nI, nG, risk = Fz["nI"], Fz["nG"], Fz["risk"]
    scores = {"I-only": nI, "G-only": nG, "Mean": (nI + nG) / 2, "Maximum": np.maximum(nI, nG), "Product": nI * nG}
    if (rdir / "classic.npz").exists():
        z = np.load(rdir / "classic.npz"); scores.update({k: z[k] for k in z.files})
    if (rdir / "lstm_ae.npz").exists():
        scores["LSTM-AE"] = np.load(rdir / "lstm_ae.npz")["score"]
    ci = {}
    for k, s in scores.items():
        ci[k] = bootstrap_ap_diff(risk[test], np.nan_to_num(s[test], nan=np.nanmin(s[test])), y, users, cfg["evaluation"]["bootstrap"])
    nvd = df.loc[val, "day"].nunique(); B = cfg["budget"]["alerts_per_day"]
    det = {}
    for k, s in [("I", nI), ("G", nG), ("FLAITD", risk)]:
        tau = budget_threshold(s[val], nvd, B)
        det[k] = set(users[(s[test] >= tau) & (y == 1)])
    extra = dict(bootstrap_vs_flaitd=ci,
                 insiders_only_I=sorted(det["I"] - det["G"]), insiders_only_G=sorted(det["G"] - det["I"]),
                 insiders_both=sorted(det["I"] & det["G"]), insiders_flaitd=sorted(det["FLAITD"]))
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import precision_recall_curve
        fig, ax = plt.subplots(figsize=(3.5, 2.6), dpi=300)
        styles = [("FLAITD", risk, "-", "#1f4e79"), ("I-only", nI, "--", "#c55a11"), ("G-only", nG, ":", "#548235"),
                  ("Mean", (nI + nG) / 2, "-.", "#7f6000")]
        for name, s, ls, c in styles:
            p, r, _ = precision_recall_curve(y, s[test])
            ax.plot(r, p, ls, color=c, lw=1.2, label=name)
        ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.legend(frameon=False, fontsize=7)
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout(); fig.savefig(Path(cfg["results_dir"]) / "fig_pr_curves_seed0.png"); plt.close(fig)
    except Exception as e:
        log(f"report: PR figure skipped ({e})")
    return extra


def dataset_stats(cfg, df):
    cache = Path(cfg["cache_dir"])
    st = {}
    for f in ["ingest_meta.json", "sessions_meta.json"]:
        if (cache / f).exists():
            st[f] = json.load(open(cache / f))
    per = df.groupby("period").agg(sessions=("sid", "size"), malicious=("mal", "sum"), days=("day", "nunique"),
                                   insiders_active=("owner", lambda u: u[df.loc[u.index, "mal"] == 1].nunique()))
    st["per_period"] = per.to_dict()
    ins = pd.read_csv(cache / "insiders.csv")
    st["insiders_per_scenario"] = ins.groupby("scenario")["user"].nunique().to_dict()
    st["sessions_total"] = int(len(df)); st["malicious_total"] = int(df["mal"].sum())
    st["base_rate_test"] = float(df.loc[df["period"] == "test", "mal"].mean())
    st["all_benign_accuracy_test"] = 1 - st["base_rate_test"]
    return st


def write_report(df, cfg, results):
    out = Path(cfg["results_dir"]); out.mkdir(parents=True, exist_ok=True)
    T = build_tables(results)
    extra = seed0_extras(df, cfg)
    stats = dataset_stats(cfg, df)
    md = [f"# FLAITD results — run `{cfg['run_name']}`", "",
          f"Seeds: {[r['seed'] for r in results]}. Values are mean ± std over seeds. Budget B = {cfg['budget']['alerts_per_day']} alerts/day.", ""]
    titles = {"IV_main": "Table IV — comparison with baselines (test period)", "V_fusion": "Table V — fusion rules",
              "VI_ablation": "Table VI — ablation", "VII_scenario": "Table VII — insiders detected per scenario",
              "VIII_keywords": "Table VIII — without keyword features"}
    for k, t in T.items():
        t.to_csv(out / f"table_{k}.csv")
        md += [f"## {titles[k]}", "", _md(t), ""]
    fz = [r["tables"]["fusion"]["FLAITD"] for r in results]
    md += ["## Fuzzy breakpoints", "", *[f"- seed {r['seed']}: {f.get('fuzzy_params')} ({f.get('fuzzy_how')})" for r, f in zip(results, fz)], ""]
    st_notes = {r["tables"]["fusion"]["Stacking (LR)"].get("note") for r in results}
    md += ["## Notes", "", *[f"- Stacking: {n}" for n in st_notes if n], ""]
    if extra:
        md += ["## Seed 0: paired bootstrap over users, PR-AUC(FLAITD) − PR-AUC(method)", "",
               "| Method | mean diff | 95% CI | P(diff ≤ 0) |", "|---|---|---|---|"]
        for k, v in extra["bootstrap_vs_flaitd"].items():
            md.append(f"| {k} | {v['mean']:.3f} | [{v['lo']:.3f}, {v['hi']:.3f}] | {v['p_le_0']:.3f} |")
        md += ["", f"Insiders detected by I-only but not G-only: {len(extra['insiders_only_I'])}; by G-only but not I-only: "
               f"{len(extra['insiders_only_G'])}; by both: {len(extra['insiders_both'])} (these one-branch cases are what AND fusion loses).", ""]
    md += ["## Dataset statistics", "", "```", json.dumps(stats, indent=1, default=str), "```", ""]
    tim = pd.DataFrame([r["timing"] for r in results]).mean().round(1).to_dict()
    md += ["## Run time (mean over seeds, seconds)", "", "```", json.dumps(tim, indent=1), "```", ""]
    ex = out / "explanations" / "deletion_test.json"
    if ex.exists():
        md += ["## Deletion test (seed 0)", "", "```", ex.read_text(), "```", "",
               f"Case studies: `{(out / 'explanations' / 'case_studies.json').as_posix()}`", ""]
    (out / "RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    json.dump(dict(stats=stats, extra=extra), open(out / "summary.json", "w"), indent=1, default=str)
    log(f"report: wrote {out / 'RESULTS.md'}")
