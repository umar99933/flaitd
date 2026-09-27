"""Supplementary check: MUEBA reimplementation without its keyword features (job_search, hacking_sites).

Answers whether MUEBA's advantage over FLAITD comes from labels or from the keyword features, next to
Table VIII. Writes results/<run>/extra/mueba_no_keywords.json; the main results are not touched.
Usage: python tools/mueba_no_keywords.py [--seeds 0 1 2 3 4]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flaitd.config import load_config  # noqa: E402
from flaitd.features import MUEBA_FEATURES  # noqa: E402
from flaitd.metrics import evaluate  # noqa: E402
from flaitd.mueba import run_mueba  # noqa: E402

KEYWORD_FEATS = {"n_job", "n_hack"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--seeds", type=int, nargs="*", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    seeds = cfg["seeds"] if args.seeds is None else args.seeds
    df = pd.read_parquet(Path(cfg["cache_dir"]) / "sessions.parquet")
    test = (df["period"] == "test").to_numpy()
    tdf = df.loc[test, ["user", "owner", "owner_scenario", "insider"]].reset_index(drop=True)
    yt = df.loc[test, "mal"].to_numpy()
    feats = [f for f in MUEBA_FEATURES if f not in KEYWORD_FEATS]
    out_dir = Path(cfg["results_dir"]) / "extra"; out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "mueba_no_keywords.json"
    res = json.load(open(out_file)) if out_file.exists() else {}
    mc = cfg["mueba"]
    for s in seeds:
        if str(s) in res:
            continue
        m = run_mueba(df, cfg, s, feats=feats)
        r = {"MUEBA (reimpl.)": evaluate(tdf, yt, alert=np.asarray(m["alert"])[test].astype(bool)),
             "MUEBA LSTM part": evaluate(tdf, yt, score=m["p_lstm"][test], tau=mc["threshold_lstm"]),
             "MUEBA iForest part": evaluate(tdf, yt, score=m["s_iforest"][test], tau=mc["threshold_iforest"])}
        res[str(s)] = {"features": feats, "metrics": r}
        json.dump(res, open(out_file, "w"), indent=1, default=float)
        print(f"seed {s} done", flush=True)


if __name__ == "__main__":
    main()
