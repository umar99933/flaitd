"""Pre-flight check of the raw CERT folder: file presence, headers, date format, LDAP and answer layout.
Run this first on real data; it reads only the first lines of each file."""
from pathlib import Path

import pandas as pd

from .ingest import COLS, DATE_FMT, ID_RE, _has_header


def run_check(cfg):
    ok = True
    d, a = Path(cfg["data_dir"]), Path(cfg["answers_dir"])
    print(f"data_dir    = {d}\nanswers_dir = {a}")
    for kind in COLS:
        f = d / f"{kind}.csv"
        if not f.exists():
            print(f"[MISSING] {f}"); ok = False; continue
        hdr = _has_header(f)
        first = open(f, errors="ignore").readline().strip()
        second = open(f, errors="ignore").readlines(4096)[1 if hdr else 0].strip()
        date = second.split(",")[1] if "," in second else ""
        try:
            pd.to_datetime(date, format=DATE_FMT); dok = "ok"
        except Exception:
            dok = "UNEXPECTED FORMAT"; ok = False
        print(f"[{kind:6}] {f.stat().st_size / 1e9:6.2f} GB  header={'yes' if hdr else 'no '}  date '{date}' {dok}")
        if hdr:
            cols = [c.strip().lower() for c in first.split(",")]
            miss = [c for c in COLS[kind] if c not in cols and c != "content"]
            if miss:
                print(f"         header lacks {miss}; found {cols}"); ok = False
        if not ID_RE.search(second):
            print(f"         first record has no {{XXXX-XXXXXXXX-XXXXXXXX}} id: {second[:80]}"); ok = False
    ldap = sorted((d / "LDAP").glob("*.csv"))
    print(f"[LDAP  ] {len(ldap)} monthly files ({ldap[0].stem} .. {ldap[-1].stem})" if ldap else "[MISSING] LDAP/*.csv")
    if ldap:
        cols = [c.strip().lower() for c in pd.read_csv(ldap[0], nrows=1).columns]
        need = ["user_id", "role", "business_unit", "functional_unit", "department"]
        print(f"         columns ok" if all(c in cols for c in need) else f"         MISSING {set(need) - set(cols)}")
        ok &= bool(ldap) and all(c in cols for c in need)
    ins = a / "insiders.csv"
    if not ins.exists():
        print(f"[MISSING] {ins}"); return False
    df = pd.read_csv(ins); df.columns = [c.strip().lower() for c in df.columns]
    sel = df[df["dataset"].astype(str).str.strip() == str(cfg["dataset_version"])]
    found = sum(1 for x in sel["details"] if list(a.rglob(str(x))))
    print(f"[answers] {len(sel)} insiders for release {cfg['dataset_version']} "
          f"(per scenario {sel.groupby('scenario').size().to_dict()}); detail files found: {found}/{len(sel)}")
    ok &= found == len(sel) and len(sel) > 0
    print("CHECK PASSED" if ok else "CHECK FOUND PROBLEMS - fix paths/config before running")
    return ok
