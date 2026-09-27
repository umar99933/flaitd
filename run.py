"""FLAITD command line.

    python run.py --config config/chunk.yaml all          # every stage
    python run.py --config config/default.yaml ingest     # one stage
Stages: check (pre-flight, optional), ingest -> sessions -> features -> audit -> experiment -> explain -> report   (all = the whole chain)
"""
import argparse
import json
import time
from pathlib import Path

import pandas as pd

from flaitd.config import load_config
from flaitd.log import log

STAGES = ["ingest", "sessions", "features", "audit", "experiment", "explain", "report"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=STAGES + ["all", "check", "prepare"])
    ap.add_argument("--config", default=None)
    ap.add_argument("--seeds", type=int, nargs="*", default=None)
    ap.add_argument("--force", action="store_true", help="recompute cached data stages")
    a = ap.parse_args()
    cfg = load_config(a.config)
    Path(cfg["results_dir"]).mkdir(parents=True, exist_ok=True)
    json.dump(cfg, open(Path(cfg["results_dir"]) / "config_used.json", "w"), indent=1)
    if a.stage == "check":
        from flaitd.check import run_check
        raise SystemExit(0 if run_check(cfg) else 1)
    todo = STAGES if a.stage == "all" else [a.stage]
    if a.stage == "prepare":
        todo = ["ingest", "sessions", "features", "audit"]
    t0 = time.time()
    df = None
    for st in todo:
        log(f"=== stage {st} ===")
        if st == "ingest":
            from flaitd.ingest import ingest; ingest(cfg, force=a.force)
        elif st == "sessions":
            from flaitd.sessions import build_sessions; build_sessions(cfg, force=a.force)
        elif st == "features":
            from flaitd.features import build_features; df = build_features(cfg, force=a.force)
        else:
            if df is None:
                df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
            if st == "audit":
                from flaitd.audit import run_audit; run_audit(cfg)
            elif st == "experiment":
                from flaitd.pipeline import run_all; run_all(df, cfg, a.seeds)
            elif st == "explain":
                from flaitd.explain import run_explain; run_explain(df, cfg, seed=(a.seeds or cfg["seeds"])[0])
            elif st == "report":
                from flaitd.report import write_report
                seeds = a.seeds if a.seeds is not None else cfg["seeds"]
                res = [json.load(open(Path(cfg["results_dir"]) / f"seed_{s}" / "metrics.json"))
                       for s in seeds if (Path(cfg["results_dir"]) / f"seed_{s}" / "metrics.json").exists()]
                write_report(df, cfg, res)
    log(f"finished {todo} in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
