"""Build logon sessions and assign every device, file, e-mail and web event to a session.

A session starts at a Logon and ends at the next Logoff by the same user on the same PC. CERT records
screen unlocks as logons, so a repeat logon on the same day with no logoff in between continues the
session (`_merge_unlocks`). CERT may also contain logons with no matching logoff; pairing those naively yields sessions that last for
months (the cause of the 9,000-hour durations in the earlier draft). Such an *orphan* session is closed
at the last event seen on that PC before the next logon, or at the end of the working day when no
later event exists. Every session is capped at `max_duration_hours`.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from .log import log

EVENT_KINDS = ["device", "file", "email", "http"]
BATCH = 2_000_000


class KeyCoder:
    """Encode (user, pc) pairs as one int64 key so merge_asof works on large tables cheaply."""

    def __init__(self, users, pcs):
        self.u = {u: i for i, u in enumerate(sorted(set(users)))}
        self.p = {p: i for i, p in enumerate(sorted(set(pcs)))}
        self.np_ = len(self.p) + 1

    def key(self, user, pc):
        u = pd.Series(user).map(self.u).fillna(-1).astype(np.int64).values
        p = pd.Series(pc).map(self.p).fillna(len(self.p)).astype(np.int64).values
        return u * self.np_ + p


def _merge_unlocks(lg):
    """Drop logons that are screen unlocks, carrying their label to the logon that opened the session.

    The r4.2 readme: "Screen unlocks are recorded as logons. Screen locks are not recorded." A logon that
    follows a logon by the same user on the same PC on the same day, with no logoff in between, is
    therefore an unlock and continues the running session. `lg` must be sorted by user, pc, time.
    """
    prev_same = (lg["user"].shift(1) == lg["user"]) & (lg["pc"].shift(1) == lg["pc"])
    unlock = (prev_same & (lg["act"] == 1) & (lg["act"].shift(1) == 1)
              & (lg["time"].dt.normalize() == lg["time"].shift(1).dt.normalize()))
    head = (~unlock).cumsum()                       # an opening logon (or a logoff) plus its unlocks
    lg = lg.assign(mal=lg.groupby(head)["mal"].transform("max"))
    return lg[~unlock].reset_index(drop=True), int(unlock.sum())


def _pair_logons(lg, cfg):
    lg = lg.sort_values(["user", "pc", "time", "act"], ascending=[True, True, True, False]).reset_index(drop=True)
    n_unlocks = 0
    if cfg.get("sessions", {}).get("merge_unlocks", True):
        lg, n_unlocks = _merge_unlocks(lg)
    same_next = (lg["user"].shift(-1) == lg["user"]) & (lg["pc"].shift(-1) == lg["pc"])
    nxt_act = lg["act"].shift(-1).where(same_next)
    nxt_time = lg["time"].shift(-1).where(same_next)
    nxt_mal = lg["mal"].shift(-1).where(same_next).fillna(0)
    s = lg[lg["act"] == 1].copy()
    idx = s.index
    s["logoff_found"] = (nxt_act.loc[idx] == 0).values
    s["end"] = np.where(s["logoff_found"], nxt_time.loc[idx], pd.NaT)
    s["end"] = pd.to_datetime(s["end"])
    s["next_logon"] = pd.to_datetime(np.where(nxt_act.loc[idx] == 1, nxt_time.loc[idx], pd.NaT))
    s["mal_logon"] = s["mal"].astype(np.int16)
    s["mal_logoff"] = np.where(s["logoff_found"], nxt_mal.loc[idx], 0).astype(np.int16)
    s = s.rename(columns={"time": "start"}).drop(columns=["act", "mal"]).reset_index(drop=True)
    s["sid"] = np.arange(len(s), dtype=np.int64)
    s.attrs["unlocks_merged"] = n_unlocks
    return s


def _iter_events(cache, kind, cols):
    f = Path(cache) / f"events_{kind}.parquet"
    if not f.exists():
        return
    for b in pq.ParquetFile(f).iter_batches(batch_size=BATCH, columns=cols):
        yield b.to_pandas()


def _asof(ev, sess_keyed):
    """Attach to each event the latest session (same key) that started at or before it."""
    ev = ev.sort_values("time")
    m = pd.merge_asof(ev, sess_keyed, left_on="time", right_on="start", by="key", direction="backward")
    return m


def build_sessions(cfg, force=False):
    cache = Path(cfg["cache_dir"])
    out = cache / "sessions_raw.parquet"
    if out.exists() and not force:
        log("sessions: cached, skipping")
        return pd.read_parquet(out)
    sc = cfg["sessions"]
    lg = pd.read_parquet(cache / "events_logon.parquet")
    s = _pair_logons(lg, cfg)
    n_unlocks = s.attrs.get("unlocks_merged", 0)

    pcs = set(lg["pc"].unique())
    for kind in EVENT_KINDS:
        for ev in _iter_events(cache, kind, ["pc"]):
            pcs |= set(ev["pc"].unique())
    coder = KeyCoder(lg["user"].unique(), pcs)
    s["key"] = coder.key(s["user"].values, s["pc"].values)
    keyed = s[["key", "start", "sid"]].sort_values("start")

    # ---- pass 1: last event per session (for orphan repair)
    last_ev = pd.Series(pd.NaT, index=s["sid"], dtype="datetime64[ns]")
    horizon = s.set_index("sid")["next_logon"].fillna(s.set_index("sid")["start"] + pd.Timedelta(hours=sc["max_duration_hours"]))
    for kind in EVENT_KINDS:
        for ev in _iter_events(cache, kind, ["user", "pc", "time"]):
            ev["key"] = coder.key(ev["user"].values, ev["pc"].values)
            m = _asof(ev[["key", "time"]], keyed).dropna(subset=["sid"])
            m["sid"] = m["sid"].astype(np.int64)
            m = m[m["time"] < horizon.loc[m["sid"]].values]
            mx = m.groupby("sid")["time"].max()
            last_ev.loc[mx.index] = np.maximum(last_ev.loc[mx.index].fillna(pd.Timestamp.min).values, mx.values)

    # ---- close orphans and cap
    orphan = ~s["logoff_found"]
    le = last_ev.loc[s["sid"]].values
    day = s["start"].dt.normalize()
    wd_end = day + pd.Timedelta(hours=sc["workday_end_hour"])
    wd_end = wd_end.where(s["start"] < wd_end, day + pd.Timedelta(hours=23, minutes=59, seconds=59))
    orphan_end = pd.Series(le, index=s.index).where(pd.Series(le, index=s.index) > s["start"], wd_end)
    end = s["end"].where(~orphan, orphan_end)
    end = end.where(s["next_logon"].isna() | (end <= s["next_logon"]), s["next_logon"])
    cap = s["start"] + pd.Timedelta(hours=sc["max_duration_hours"])
    s["capped"] = (end > cap).astype(np.int8)
    s["end"] = end.where(end <= cap, cap)
    s["orphan"] = orphan.astype(np.int8)

    # ---- pass 2: assign events and aggregate raw counts
    n = len(s)
    acc = {c: np.zeros(n, dtype=np.int64) for c in
           ["n_device", "n_usb", "n_file", "n_email", "n_email_ext", "n_attach", "n_http", "n_job", "n_hack", "n_leak", "mal_events"]}
    owner = np.maximum(s["mal_logon"].to_numpy(), s["mal_logoff"].to_numpy()).astype(np.int64)
    ext_pairs = []
    grace = pd.Timedelta(minutes=sc["event_grace_minutes"])
    end_by_sid = s.set_index("sid")["end"]
    stats = {}
    cols = {"device": ["user", "pc", "time", "connect", "mal"], "file": ["user", "pc", "time", "ext", "mal"],
            "email": ["user", "pc", "time", "ext_rcpt", "n_attach", "mal"], "http": ["user", "pc", "time", "job", "hack", "leak", "mal"]}
    for kind in EVENT_KINDS:
        tot = kept = mal_tot = mal_kept = 0
        for ev in _iter_events(cache, kind, cols[kind]):
            ev["key"] = coder.key(ev["user"].values, ev["pc"].values)
            tot += len(ev); mal_tot += int((ev["mal"] > 0).sum())
            m = _asof(ev.drop(columns=["user", "pc"]), keyed).dropna(subset=["sid"])
            m["sid"] = m["sid"].astype(np.int64)
            m = m[m["time"] <= (end_by_sid.loc[m["sid"]].values + grace)]
            kept += len(m); mal_kept += int((m["mal"] > 0).sum())
            sid = m["sid"].values
            np.add.at(acc["mal_events"], sid, (m["mal"].values > 0).astype(np.int64))
            np.maximum.at(owner, sid, m["mal"].values.astype(np.int64))
            if kind == "device":
                np.add.at(acc["n_device"], sid, 1); np.add.at(acc["n_usb"], sid, m["connect"].values)
            elif kind == "file":
                np.add.at(acc["n_file"], sid, 1)
                ext_pairs.append(m.loc[m["ext"] != "", ["sid", "ext"]].drop_duplicates())
            elif kind == "email":
                np.add.at(acc["n_email"], sid, 1); np.add.at(acc["n_email_ext"], sid, m["ext_rcpt"].values)
                np.add.at(acc["n_attach"], sid, m["n_attach"].values)
            elif kind == "http":
                np.add.at(acc["n_http"], sid, 1)
                for c in ["job", "hack", "leak"]:
                    np.add.at(acc[f"n_{c}"], sid, m[c].values)
        stats[kind] = dict(events=tot, assigned=kept, unassigned=tot - kept, malicious=mal_tot, malicious_assigned=mal_kept)
        log(f"sessions: {kind}: {kept:,}/{tot:,} events assigned; malicious {mal_kept}/{mal_tot}")
    for k, v in acc.items():
        s[k] = v
    s["n_file_ext"] = 0
    if ext_pairs:
        e = pd.concat(ext_pairs).drop_duplicates().groupby("sid").size()
        s.loc[e.index, "n_file_ext"] = e.values
    s["mal_owner"] = owner.astype(np.int16)          # 1-based row of insiders.csv, 0 if benign
    s["mal"] = ((s["mal_logon"] > 0) | (s["mal_logoff"] > 0) | (s["mal_events"] > 0)).astype(np.int8)
    s = s.drop(columns=["key", "next_logon"])
    s.to_parquet(out)
    stats.update(sessions=int(n), unlocks_merged=n_unlocks, orphan_sessions=int(s["orphan"].sum()), capped=int(s["capped"].sum()),
                 malicious_sessions=int(s["mal"].sum()), logon_rows=int(len(lg)))
    json.dump(stats, open(cache / "sessions_meta.json", "w"), indent=2)
    log(f"sessions: {n:,} sessions, {n_unlocks:,} screen unlocks merged, {int(s['orphan'].sum()):,} orphans repaired, "
        f"{int(s['mal'].sum())} malicious")
    return s
