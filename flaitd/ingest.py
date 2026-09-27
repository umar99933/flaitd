"""Stream the raw CERT CSV files into compact per-event parquet tables.

The raw http.csv of r4.2 is over 10 GB, so every file is read in chunks and only the fields the
pipeline needs are kept. Each event row carries a `mal` flag (1 if its event id is in the answer key).
"""
import json
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .log import log

COLS = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
}
KEEP = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "attachments"],
    "http": ["id", "date", "user", "pc", "url"],
}
DATE_FMT = "%m/%d/%Y %H:%M:%S"
ID_RE = re.compile(r"\{[A-Z0-9]{4}-[A-Z0-9]{8}-[A-Z0-9]{8}\}")


# ----------------------------------------------------------------------------- answers / LDAP
def load_insiders(cfg):
    """Return a DataFrame of insiders (user, scenario, start, end, details) for the configured release."""
    ans = Path(cfg["answers_dir"])
    df = pd.read_csv(ans / "insiders.csv")
    df.columns = [c.strip().lower() for c in df.columns]
    df = df[df["dataset"].astype(str).str.strip() == str(cfg["dataset_version"])].copy()
    df["scenario"] = df["scenario"].astype(int)
    return df.reset_index(drop=True)


def load_malicious_ids(cfg, insiders):
    """Collect every event id listed in the per-insider answer files."""
    ans = Path(cfg["answers_dir"])
    ids, per_user, missing = {}, {}, []
    for _, r in insiders.iterrows():
        hits = list(ans.rglob(str(r["details"])))
        if not hits:
            missing.append(r["details"])
            continue
        found = set(ID_RE.findall(hits[0].read_text(errors="ignore")))
        per_user[r["user"]] = len(found)
        for i in found:          # value = 1-based insider row: which insider the event belongs to
            ids[i] = int(r.name) + 1
    if missing:
        log(f"WARNING: {len(missing)} answer files not found, e.g. {missing[:3]}")
    return ids, per_user


def load_ldap(cfg):
    """Monthly LDAP snapshots -> one row per (month, user)."""
    rows = []
    for f in sorted((Path(cfg["data_dir"]) / "LDAP").glob("*.csv")):
        m = pd.read_csv(f)
        m.columns = [c.strip().lower() for c in m.columns]
        m["month"] = f.stem  # e.g. 2010-01
        rows.append(m)
    ldap = pd.concat(rows, ignore_index=True)
    ldap = ldap.rename(columns={"user_id": "user"})
    for c in ["role", "business_unit", "functional_unit", "department", "team", "supervisor"]:
        if c not in ldap.columns:
            ldap[c] = ""
        ldap[c] = ldap[c].fillna("").astype(str)
    return ldap[["month", "user", "role", "business_unit", "functional_unit", "department", "team", "supervisor"]]


def select_users(cfg, ldap, insiders):
    """Return the set of users to analyse (None means all)."""
    ucfg = cfg["users"]
    if ucfg["mode"] == "all":
        return None
    rng = np.random.default_rng(ucfg["seed"])
    ins = sorted(insiders["user"].unique())
    if ucfg.get("n_insiders"):
        ins = sorted(rng.choice(ins, size=min(ucfg["n_insiders"], len(ins)), replace=False))
    benign = sorted(set(ldap["user"]) - set(insiders["user"]))
    ben = rng.choice(benign, size=min(ucfg["n_benign"], len(benign)), replace=False)
    return set(ins) | set(ben)


# ----------------------------------------------------------------------------- CSV streaming
def _has_header(path):
    with open(path, "r", errors="ignore") as fh:
        return fh.readline().lower().startswith("id,")


def _reader(path, kind, chunksize):
    header = _has_header(path)
    names = COLS[kind]
    kw = dict(chunksize=chunksize, dtype=str, keep_default_na=False, on_bad_lines="skip", engine="c")
    if header:
        first = pd.read_csv(path, nrows=0)
        cols = [c.strip().lower() for c in first.columns]
        use = [c for c in KEEP[kind] if c in cols]
        return pd.read_csv(path, usecols=lambda c: c.strip().lower() in use, **kw), True
    idx = [names.index(c) for c in KEEP[kind]]
    return pd.read_csv(path, header=None, names=names, usecols=idx, **kw), False


def _kw_pattern(words):
    return "|".join(re.escape(w.lower()) for w in words)


def keyword_hits(url, words, exclude_hosts=()):
    """Flag URLs that match a keyword list, looking only at the host and the first path segment.

    In CERT the rest of the path is filler (an article title plus scrambled text), so a plain substring
    match over the whole URL fires on words such as 'spy' or 'trojan' by chance. Term forms:
      '/jobs'               first path segment equals 'jobs' (a site section, e.g. aol.com/jobs)
      'craigslist.org/jobs' host ends with craigslist.org and first path segment is 'jobs'
      'monster.com'         substring of the host
    Hosts listed in `exclude_hosts` (or their subdomains) never match.
    """
    parts = url.str.lower().str.extract(r"^[a-z]+://([^/?#:]+)[^/?#]*/?([^/?#]*)", expand=True).fillna("")
    host, seg = parts[0], parts[1]
    hit = pd.Series(False, index=url.index)
    host_terms = [w.lower() for w in words if "/" not in w]
    if host_terms:
        hit |= host.str.contains(_kw_pattern(host_terms), regex=True)
    sections = {w.lower().strip("/") for w in words if w.startswith("/")}
    if sections:
        hit |= seg.isin(sections)
    for w in (w.lower() for w in words if "/" in w and not w.startswith("/")):
        h, s = w.split("/", 1)
        hit |= (host.str.endswith(h) & (seg == s.strip("/")))
    for h in exclude_hosts:
        h = h.lower()
        hit &= ~((host == h) | host.str.endswith("." + h))
    return hit


def _transform(kind, df, cfg):
    df.columns = [c.strip().lower() for c in df.columns]
    out = pd.DataFrame({
        "user": df["user"].values,
        "pc": df["pc"].values,
        "time": pd.to_datetime(df["date"], format=DATE_FMT, errors="coerce").values,
    })
    if kind == "logon":
        out["act"] = (df["activity"].str.strip().str.lower() == "logon").astype("int8").values
    elif kind == "device":
        out["connect"] = (df["activity"].str.strip().str.lower() == "connect").astype("int8").values
    elif kind == "file":
        out["ext"] = df["filename"].str.lower().str.extract(r"\.([a-z0-9]{1,6})$", expand=False).fillna("").values
    elif kind == "email":
        pat = r"@(?!" + re.escape(cfg["org_domain"].lower()) + r"\b)[\w.-]+"
        rcpt = (df["to"] + ";" + df["cc"] + ";" + df["bcc"]).str.lower()
        out["ext_rcpt"] = rcpt.str.contains(pat, regex=True).astype("int8").values
        att = pd.to_numeric(df["attachments"], errors="coerce")
        cnt = df["attachments"].str.count(";") + (df["attachments"].str.len() > 0).astype(int)
        out["n_attach"] = att.fillna(cnt).fillna(0).astype("int16").values
    elif kind == "http":
        kw = cfg["features"]["keywords"]
        excl = cfg["features"].get("keyword_exclude_hosts", [])
        out["job"] = keyword_hits(df["url"], kw["job"], excl).astype("int8").values
        out["hack"] = keyword_hits(df["url"], kw["hacking"], excl).astype("int8").values
        out["leak"] = keyword_hits(df["url"], kw["leak"], excl).astype("int8").values
    return out


def ingest(cfg, force=False):
    """Stream all five event files into cache_dir/events_<kind>.parquet and write metadata."""
    cache = Path(cfg["cache_dir"]); cache.mkdir(parents=True, exist_ok=True)
    meta_path = cache / "ingest_meta.json"
    if meta_path.exists() and not force:
        log("ingest: cached, skipping (use --force to redo)")
        return json.load(open(meta_path))

    insiders = load_insiders(cfg)
    mal_ids, per_user = load_malicious_ids(cfg, insiders)
    ldap = load_ldap(cfg)
    keep_users = select_users(cfg, ldap, insiders)
    insiders.to_csv(cache / "insiders.csv", index=False)
    ldap.to_parquet(cache / "ldap.parquet")
    pd.Series(sorted(keep_users) if keep_users else sorted(set(ldap["user"])), name="user").to_csv(cache / "users.csv", index=False)
    log(f"ingest: {len(insiders)} insiders, {len(mal_ids)} malicious event ids, "
        f"{'all' if keep_users is None else len(keep_users)} users selected")

    meta = {"n_mal_ids": len(mal_ids), "files": {}}
    for kind in ["logon", "device", "file", "email", "http"]:
        path = Path(cfg["data_dir"]) / f"{kind}.csv"
        t0 = time.time(); writer = None; n_in = n_out = n_mal = 0; bad_dates = 0
        reader, _ = _reader(path, kind, cfg["read_chunksize"])
        for chunk in reader:
            chunk.columns = [c.strip().lower() for c in chunk.columns]
            n_in += len(chunk)
            if keep_users is not None:
                chunk = chunk[chunk["user"].isin(keep_users)]
            if chunk.empty:
                continue
            ev = _transform(kind, chunk, cfg)
            ev["mal"] = chunk["id"].map(mal_ids).fillna(0).astype("int16").values   # 0 or owning insider (1-based)
            bad = ev["time"].isna(); bad_dates += int(bad.sum()); ev = ev[~bad]
            n_out += len(ev); n_mal += int((ev["mal"] > 0).sum())
            tbl = pa.Table.from_pandas(ev, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(cache / f"events_{kind}.parquet", tbl.schema)
            writer.write_table(tbl)
        if writer:
            writer.close()
        meta["files"][kind] = dict(rows_read=n_in, rows_kept=n_out, malicious=n_mal, bad_dates=bad_dates,
                                   seconds=round(time.time() - t0, 1))
        log(f"ingest {kind}: read {n_in:,} kept {n_out:,} malicious {n_mal:,} ({time.time()-t0:.0f}s)")
    meta["malicious_events_matched"] = sum(v["malicious"] for v in meta["files"].values())
    json.dump(meta, open(meta_path, "w"), indent=2)
    return meta
