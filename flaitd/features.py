"""Session features (Table I of the paper), day numbering and split assignment."""
from pathlib import Path

import numpy as np
import pandas as pd

from .log import log

FEATURES = ["duration_min", "logon_hour", "offhours", "weekend", "n_usb", "n_file", "n_file_ext",
            "n_email", "n_email_ext", "n_attach", "n_http", "n_job", "n_hack", "n_leak"]
COUNT_LIKE = {"duration_min", "n_usb", "n_file", "n_file_ext", "n_email", "n_email_ext", "n_attach",
              "n_http", "n_job", "n_hack", "n_leak", "n_device"}
# MUEBA Table 2 (numeric part). role and logon_PC are categorical identifiers and are used for grouping only.
MUEBA_FEATURES = ["logon_hour", "logoff_hour", "duration_min", "n_http", "n_job", "n_hack",
                  "n_email", "n_email_ext", "n_device", "n_file"]


def feature_list(cfg, drop_keywords=False):
    if drop_keywords:
        return [f for f in FEATURES if f not in cfg["features"]["keyword_features"]]
    return list(FEATURES)


def matrix(df, feats):
    """Model input: log1p on counts and duration, raw values otherwise."""
    X = np.empty((len(df), len(feats)), dtype=np.float32)
    for j, f in enumerate(feats):
        v = df[f].to_numpy(dtype=np.float64)
        X[:, j] = np.log1p(np.maximum(v, 0)) if f in COUNT_LIKE else v
    return X


def build_features(cfg, force=False):
    cache = Path(cfg["cache_dir"])
    out = cache / "sessions.parquet"
    if out.exists() and not force:
        log("features: cached, skipping")
        return pd.read_parquet(out)
    s = pd.read_parquet(cache / "sessions_raw.parquet")
    ins = pd.read_csv(cache / "insiders.csv")
    a, b = cfg["features"]["offhours"]
    s["duration_min"] = (s["end"] - s["start"]).dt.total_seconds().clip(lower=0) / 60.0
    s["logon_hour"] = s["start"].dt.hour + s["start"].dt.minute / 60.0
    s["logoff_hour"] = s["end"].dt.hour + s["end"].dt.minute / 60.0
    s["offhours"] = ((s["start"].dt.hour < a) | (s["start"].dt.hour >= b)).astype(np.int8)
    s["weekend"] = (s["start"].dt.dayofweek >= 5).astype(np.int8)
    first = s["start"].min().normalize()
    s["day"] = ((s["start"].dt.normalize() - first).dt.days + 1).astype(np.int32)
    s["month"] = s["start"].dt.strftime("%Y-%m")
    sp = cfg["split"]
    s["period"] = "none"
    for p in ["train", "val", "test"]:
        lo, hi = sp[p]
        s.loc[(s["day"] >= lo) & (s["day"] <= hi), "period"] = p
    scen = dict(zip(ins["user"], ins["scenario"]))
    s["insider"] = s["user"].isin(scen).astype(np.int8)
    s["scenario"] = s["user"].map(scen).fillna(0).astype(np.int8)
    # For malicious sessions, credit the insider who owns the events (scenario 3 acts under a supervisor's account).
    own = s["mal_owner"].to_numpy().astype(int)
    s["owner"] = np.where(own > 0, ins["user"].to_numpy()[np.maximum(own - 1, 0)], s["user"].to_numpy())
    s["owner_scenario"] = np.where(own > 0, ins["scenario"].to_numpy()[np.maximum(own - 1, 0)], s["scenario"].to_numpy()).astype(np.int8)
    s = s.sort_values(["user", "start"]).reset_index(drop=True)
    s["sid"] = np.arange(len(s), dtype=np.int64)
    s.to_parquet(out)
    summ = s.groupby("period").agg(sessions=("sid", "size"), malicious=("mal", "sum"), days=("day", "nunique"))
    log("features: split summary\n" + summ.to_string())
    summ.to_csv(cache / "split_summary.csv")
    act = s[s["mal"] == 1].groupby("period")["owner"].nunique()
    act.to_csv(cache / "insiders_active_per_period.csv")
    return s
