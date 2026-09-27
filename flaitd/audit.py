"""Data audit (run after `features`, before `experiment`). Writes results/<run>/DATA_AUDIT.md.

Everything here describes the data layout only; no model is trained and no test result is computed,
so decisions taken from it (e.g. widening the validation window) are legitimate if recorded.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .features import FEATURES
from .group import assign_groups


def _tbl(df):
    df = df.reset_index()
    cols = [str(c) for c in df.columns]
    rows = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    rows += ["| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join(rows)


def run_audit(cfg):
    cache = Path(cfg["cache_dir"]); out = Path(cfg["results_dir"]); out.mkdir(parents=True, exist_ok=True)
    s = pd.read_parquet(cache / "sessions.parquet")
    ins = pd.read_csv(cache / "insiders.csv")
    im = json.load(open(cache / "ingest_meta.json")); sm = json.load(open(cache / "sessions_meta.json"))
    md, warn = ["# Data audit", ""], []

    # 1. raw data and labels
    md += ["## 1. Raw events and answer key", "",
           _tbl(pd.DataFrame(im["files"]).T[["rows_read", "rows_kept", "malicious", "bad_dates"]]), "",
           f"Malicious event ids in answer files: {im['n_mal_ids']:,}; matched in logs: {im['malicious_events_matched']:,}.", ""]
    if im["malicious_events_matched"] < 0.95 * im["n_mal_ids"]:
        warn.append("Fewer than 95% of answer-key events were found in the logs: check id format / paths.")
    md += [f"Insiders: {len(ins)} (per scenario {ins.groupby('scenario').size().to_dict()}).", ""]

    # 2. sessions
    dur = s["duration_min"] / 60
    unassigned = {k: v["unassigned"] for k, v in sm.items() if isinstance(v, dict) and "unassigned" in v}
    md += ["## 2. Sessions", "",
           f"Sessions: {len(s):,}; malicious: {int(s['mal'].sum()):,} ({s['mal'].mean():.3%}). "
           f"Screen unlocks merged into the running session: {sm.get('unlocks_merged', 0):,}. "
           f"Orphan logons repaired: {sm['orphan_sessions']:,} ({sm['orphan_sessions'] / len(s):.1%}); capped at 24 h: {sm['capped']:,}.", "",
           f"Duration (hours): median {dur.median():.2f}, 95th pct {dur.quantile(.95):.2f}, max {dur.max():.2f}.", "",
           f"Unassigned events per type: {unassigned}.", "",
           "Reference (MUEBA): 341,794 sessions, 993 malicious.", ""]
    for k, v in sm.items():
        if isinstance(v, dict) and v.get("malicious", 0) and v["malicious_assigned"] < 0.95 * v["malicious"]:
            warn.append(f"{k}: only {v['malicious_assigned']}/{v['malicious']} malicious events assigned to a session.")

    # 3. timeline of insider activity and the split
    s["ym"] = s["start"].dt.strftime("%Y-%m")
    tl = s.groupby("ym").agg(sessions=("sid", "size"), malicious=("mal", "sum"),
                             insiders=("owner", lambda u: u[s.loc[u.index, "mal"] == 1].nunique()),
                             first_day=("day", "min"), last_day=("day", "max"))
    per = s.groupby("period").agg(sessions=("sid", "size"), malicious=("mal", "sum"),
                                  insiders=("owner", lambda u: u[s.loc[u.index, "mal"] == 1].nunique()))
    md += ["## 3. Insider activity over time and the split", "", _tbl(tl), "",
           f"Current split: {cfg['split']}", "", _tbl(per), ""]
    nval = int(per.loc["val", "malicious"]) if "val" in per.index else 0
    mv = cfg["stacking"]["min_val_positives"]
    if nval < mv:
        warn.append(f"Validation period has {nval} malicious sessions (< {mv}): fuzzy breakpoints would stay at defaults "
                    f"and stacking would fall back. Decide NOW (before `experiment`) whether to widen `split.val`; "
                    f"use the monthly table above and record the choice in CHANGES.md.")
    ntr = int(per.loc["train", "malicious"]) if "train" in per.index else 0
    md += [f"Malicious sessions in training period: {ntr} (removed from individual-branch training targets; "
           f"MUEBA's classifier needs some).", ""]

    # 4. scenario profiles (description only)
    prof = s[s["mal"] == 1].groupby("owner_scenario")[FEATURES].mean().round(2)
    prof.loc["benign"] = s.loc[s["mal"] == 0, FEATURES].mean().round(2)
    md += ["## 4. Mean feature values: malicious sessions per scenario vs benign", "", _tbl(prof.T), ""]

    # 5. keyword features: overall hit rates (no labels involved)
    kw = pd.DataFrame({f: [(s[f] > 0).mean(), s.loc[s[f] > 0, "user"].nunique()] for f in ["n_job", "n_hack", "n_leak"]},
                      index=["share of sessions with a hit", "users with a hit"]).T
    md += ["## 5. Keyword features (hit rates over all sessions, no labels)", "", _tbl(kw.round(4)), "",
           "A list that fires in a large share of sessions is too broad; a list that never fires is useless. "
           "Adjust lists only on general grounds, never by looking at which insiders they catch.", ""]
    for f, r in kw.iterrows():
        if r.iloc[0] > 0.3:
            warn.append(f"{f} fires in {r.iloc[0]:.0%} of sessions - keyword list probably too broad.")
        if r.iloc[0] == 0:
            warn.append(f"{f} never fires - keyword list does not match this data's URLs.")

    # 6. peer groups
    a = assign_groups(cfg, s)
    g = a.groupby("gkind")["user"].size().rename("user-months")
    sizes = a.groupby(["month", "gkey"])["user"].nunique()
    md += ["## 6. Peer groups", "", f"Distinct roles: {a['role'].nunique()}.", "", _tbl(g.to_frame()), "",
           f"Group size per month: median {sizes.median():.0f}, min {sizes.min()}, max {sizes.max()}.", ""]

    # 7. users
    spu = s.groupby("user").size()
    md += ["## 7. Users", "", f"Users with sessions: {spu.size}; sessions per user: median {spu.median():.0f}, "
           f"min {spu.min()}; users with < 10 sessions (too short a history for w = 10): {(spu < 10).sum()}.", ""]

    md = md[:2] + ["## Warnings", ""] + ([f"- **{w}**" for w in warn] or ["- none"]) + [""] + md[2:]
    (out / "DATA_AUDIT.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(["AUDIT WARNINGS:"] + (warn or ["none"]) + [f"report: {out / 'DATA_AUDIT.md'}"]))
    return warn
