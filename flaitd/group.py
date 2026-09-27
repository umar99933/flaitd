"""Peer-group branch (Section IV-C).

Peer groups are formed per month from the LDAP snapshots: users with the same role, or, for roles with
fewer than `min_group_size` users, the users of the same functional unit and department (then business
unit, then everyone). For group g and month n, an Isolation Forest is fitted on the group's sessions in
month n-1 (earlier months are added if the pool is small) and scores the group's sessions in month n.
"""
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import matrix
from .itree import IsoForest
from .log import log


def user_attributes(cfg, df, static=False):
    """(month, user) -> role / unit attributes, filled forward and backward for months a user is absent."""
    ldap = pd.read_parquet(Path(cfg["cache_dir"]) / "ldap.parquet")
    users = df["user"].unique()
    months = sorted(set(df["month"]) | set(ldap["month"]))
    ldap = ldap[ldap["user"].isin(users)]
    grid = pd.MultiIndex.from_product([months, users], names=["month", "user"]).to_frame(index=False)
    a = grid.merge(ldap, on=["month", "user"], how="left").sort_values(["user", "month"])
    cols = ["role", "business_unit", "functional_unit", "department"]
    a[cols] = a.groupby("user")[cols].transform(lambda s: s.ffill().bfill())
    a[cols] = a[cols].fillna("unknown")
    if static:
        first = a.groupby("user")[cols].transform("first")
        a[cols] = first
    return a


def assign_groups(cfg, df, static=False, fallback=True, min_size=None):
    """Return a DataFrame (month, user, gkey, gkind) giving each user's peer group per month."""
    gc = cfg["group"]
    min_size = gc["min_group_size"] if min_size is None else min_size
    a = user_attributes(cfg, df, static)
    active = df[["month", "user"]].drop_duplicates()
    a = a.merge(active, on=["month", "user"])
    a["k_role"] = "role:" + a["role"]
    a["k_fu"] = "fu:" + a["functional_unit"] + "|" + a["department"]
    a["k_bu"] = "bu:" + a["business_unit"]
    a["k_all"] = "all"
    a["gkey"] = a["k_role"]; a["gkind"] = "role"
    if fallback:
        for level in ["k_role", "k_fu", "k_bu"]:
            size = a.groupby(["month", level])["user"].transform("nunique")
            nxt = {"k_role": "k_fu", "k_fu": "k_bu", "k_bu": "k_all"}[level]
            small = (a["gkey"] == a[level]) & (size < min_size)
            a.loc[small, "gkey"] = a.loc[small, nxt]
            a.loc[small, "gkind"] = nxt[2:]
    return a


def _members(a, key, month):
    """Users that belong to peer group `key` in `month` (all users sharing that attribute value)."""
    kind = key.split(":")[0]
    col = {"role": "k_role", "fu": "k_fu", "bu": "k_bu", "all": "k_all"}[kind]
    return set(a.loc[(a["month"] == month) & (a[col] == key), "user"])


def pool_index(df, a, key, month, months, gc):
    """Row indices used to fit the forest for (key, month)."""
    mem = _members(a, key, month)
    in_group = df["user"].isin(mem).to_numpy()
    i = months.index(month)
    idx = np.array([], dtype=np.int64)
    for back in range(1, gc["max_back_months"] + 1):
        if i - back < 0:
            break
        idx = np.concatenate([idx, np.flatnonzero(in_group & (df["month"] == months[i - back]).to_numpy())])
        if len(idx) >= gc["min_pool"]:
            return idx, False
    cur = np.flatnonzero(in_group & (df["month"] == month).to_numpy())
    return np.concatenate([idx, cur]), True   # transductive fallback (first month or tiny group)


def make_forest(gc, seed, n):
    if gc["tree_type"] == "eif":
        return IsoForest(gc["n_trees"], gc["max_samples"], mode="eif", seed=seed)
    return IsolationForest(n_estimators=gc["n_trees"], max_samples=min(gc["max_samples"], n), random_state=seed)


def forest_score(forest, X):
    if isinstance(forest, IsolationForest):
        return -forest.score_samples(X)
    return forest.score(X)


def run_group(df, cfg, feats, seed, static=None, fallback=None, tree_type=None):
    gc = dict(cfg["group"])
    if tree_type:
        gc["tree_type"] = tree_type
    static = gc["static_roles"] if static is None else static
    fallback = gc["fallback"] if fallback is None else fallback
    t0 = time.time()
    a = assign_groups(cfg, df, static=static, fallback=fallback)
    X = matrix(df, feats).astype(np.float64)
    gmap = a.set_index(["month", "user"])["gkey"]
    gkey = gmap.reindex(pd.MultiIndex.from_arrays([df["month"], df["user"]])).to_numpy()
    months = sorted(df["month"].unique())
    score = np.full(len(df), np.nan)
    n_fits = n_transductive = 0
    for (key, month), rows in pd.DataFrame({"k": gkey, "m": df["month"].to_numpy()}).groupby(["k", "m"]).groups.items():
        rows = np.asarray(rows)
        pidx, trans = pool_index(df, a, key, month, months, gc)
        if len(pidx) < 2:
            pidx, trans = rows, True
        forest = make_forest(gc, seed, len(pidx)).fit(X[pidx])
        score[rows] = forest_score(forest, X[rows])
        n_fits += 1; n_transductive += int(trans)
    log(f"group seed={seed}: {n_fits} group-month forests ({n_transductive} transductive), {time.time() - t0:.0f}s")
    return dict(score=score, gkey=gkey, assign=a, seconds=time.time() - t0, n_fits=n_fits,
                n_transductive=n_transductive, gc=gc)


def refit_for_rows(df, cfg, feats, seed, res, rows):
    """Re-create the forest that scored `rows` (all in one group-month) - used for SHAP and deletion tests."""
    gc = res["gc"]; a = res["assign"]
    months = sorted(df["month"].unique())
    key, month = res["gkey"][rows[0]], df["month"].iloc[rows[0]]
    pidx, _ = pool_index(df, a, key, month, months, gc)
    if len(pidx) < 2:
        pidx = np.asarray(rows)
    X = matrix(df, feats).astype(np.float64)
    return make_forest(gc, seed, len(pidx)).fit(X[pidx])
