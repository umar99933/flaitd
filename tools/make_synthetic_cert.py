"""Generate a small synthetic dataset in the CERT r4.2 file format, for smoke-testing the pipeline only.

It reproduces the file layout (logon/device/file/email/http CSVs, LDAP/ monthly snapshots, answers/)
and injects the three r4.2 scenario patterns for a handful of insiders. Results on it mean nothing.

    python tools/make_synthetic_cert.py --out data/synthetic --users 60 --days 120
"""
import argparse
import csv
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

FMT = "%m/%d/%Y %H:%M:%S"
BENIGN = ["google.com", "yahoo.com", "cnn.com", "espn.com", "bbc.co.uk", "wikipedia.org", "amazon.com",
          "weather.com", "nytimes.com", "msn.com", "ebay.com", "reddit.com"]
JOBS = ["monster.com", "careerbuilder.com", "indeed.com", "simplyhired.com"]
HACK = ["hackingexposed.com", "keyloggerpro.com", "spytech-web.com"]
ROLES = [("ITAdmin", 4), ("Salesman", 14), ("Engineer", 16), ("Secretary", 8), ("Manager", 8), ("Scientist", 8), ("Lawyer", 2)]


def rid(r):
    part = lambda n: "".join(r.choice(string.ascii_uppercase + string.digits) for _ in range(n))
    return "{" + f"{part(4)}-{part(8)}-{part(8)}" + "}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/synthetic")
    ap.add_argument("--users", type=int, default=60)
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    r = random.Random(a.seed)
    out = Path(a.out); data = out / "r4.2"; ans = out / "answers"
    (data / "LDAP").mkdir(parents=True, exist_ok=True); ans.mkdir(parents=True, exist_ok=True)

    users = []
    scale = max(1.0, a.users / 60)
    for role, n in ROLES:
        for _ in range(int(round(n * scale))):
            if len(users) >= a.users:
                break
            uid = "".join(r.choice(string.ascii_uppercase) for _ in range(3)) + f"{r.randint(1000, 9999)}"
            dept = r.choice(["D1", "D2"]) if role not in ("ITAdmin", "Lawyer") else "D3"
            users.append(dict(user=uid, role=role, fu=f"FU-{role[:3]}" if role != "Lawyer" else "FU-Leg", dept=dept,
                              pc=f"PC-{r.randint(1000, 9999)}", usb_habit=r.random() < 0.2, night=r.random() < 0.05))
    by_role = {}
    for u in users:
        by_role.setdefault(u["role"], []).append(u)
    for u in users:
        u["sup"] = by_role["Manager"][0]["user"] if u["role"] != "Manager" else users[0]["user"]
    # insiders: 2 per scenario; one scenario-2 insider starts in the validation window
    admins = by_role["ITAdmin"]
    D = lambda x: max(1, int(round(x / 120 * a.days)))   # insider windows scale with --days
    ins = [(1, by_role["Salesman"][0], D(82), D(95)), (1, by_role["Engineer"][0], D(90), D(104)),
           (2, by_role["Engineer"][1], D(64), D(110)), (2, by_role["Secretary"][0], D(78), D(112)),
           (3, admins[0], D(85), D(92)), (3, by_role["Scientist"][0], D(95), D(101))]
    t0 = datetime(2010, 1, 2)
    ev = {k: [] for k in ["logon", "device", "file", "email", "http"]}
    mal = {}

    def add(kind, t, u, pc, *rest, bad=False, who=None):
        i = rid(r)
        ev[kind].append([i, t.strftime(FMT), u, pc, *rest])
        if bad:
            mal.setdefault(who or u, []).append([kind, i, t.strftime(FMT), u, pc, *rest])

    ins_of = {u["user"]: (sc, s, e) for sc, u, s, e in ins}
    for d in range(a.days):
        day = t0 + timedelta(days=d)
        weekend = day.weekday() >= 5
        for u in users:
            if weekend and r.random() > 0.05:
                continue
            if r.random() < 0.05:
                continue  # absent
            sc, s0, s1 = ins_of.get(u["user"], (0, 10**9, -1))
            act = s0 <= d + 1 <= s1
            start = day + timedelta(hours=r.gauss(8.5, 0.6))
            if u["night"] and r.random() < 0.3:
                start = day + timedelta(hours=r.uniform(19.5, 22))
            end = start + timedelta(hours=max(r.gauss(8.5, 1.0), 1))
            sess = [(start, end, u["pc"], False)]
            if act and sc == 1 and r.random() < 0.5:
                ns = day + timedelta(hours=r.uniform(21, 23.5)); sess.append((ns, ns + timedelta(minutes=r.uniform(20, 60)), u["pc"], True))
            for (st, en, pc, bad_s) in sess:
                add("logon", st, u["user"], pc, "Logon", bad=bad_s)
                cur = st
                n_http = max(1, int(r.gauss(20, 5)))
                for _ in range(n_http):
                    cur_t = st + (en - st) * r.random()
                    add("http", cur_t, u["user"], pc, f"http://www.{r.choice(BENIGN)}/page{r.randint(1, 999)}", "benign words")
                for _ in range(int(r.expovariate(1 / 3))):
                    to = f"{r.choice(users)['user'].lower()}@dtaa.com" if r.random() < 0.8 else f"friend{r.randint(1, 99)}@gmail.com"
                    add("email", st + (en - st) * r.random(), u["user"], pc, to, "", "", f"{u['user'].lower()}@dtaa.com",
                        str(r.randint(1000, 90000)), str(r.choice([0, 0, 0, 1, 2])), "text")
                if u["usb_habit"] and r.random() < 0.5:
                    tc = st + (en - st) * r.random()
                    add("device", tc, u["user"], pc, "Connect")
                    for _ in range(r.randint(0, 3)):
                        add("file", tc + timedelta(minutes=r.randint(1, 20)), u["user"], pc, f"F{r.randint(1, 999)}.{r.choice(['doc', 'pdf', 'xls', 'txt'])}", "c")
                    add("device", tc + timedelta(minutes=30), u["user"], pc, "Disconnect")
                if act:
                    tm = st + (en - st) * r.random()
                    if sc == 1 and bad_s:
                        add("device", tm, u["user"], pc, "Connect", bad=True)
                        for _ in range(r.randint(2, 6)):
                            add("file", tm + timedelta(minutes=2), u["user"], pc, f"S{r.randint(1, 999)}.doc", "secret", bad=True)
                        add("http", tm + timedelta(minutes=5), u["user"], pc, "http://wikileaks.org/upload", "upload", bad=True)
                    if sc == 2:
                        for _ in range(r.randint(1, 4)):
                            add("http", tm, u["user"], pc, f"http://www.{r.choice(JOBS)}/search?q=job", "job", bad=True)
                        if d + 1 > s1 - 6:
                            add("device", tm, u["user"], pc, "Connect", bad=True)
                            for _ in range(r.randint(5, 15)):
                                add("file", tm + timedelta(minutes=3), u["user"], pc, f"P{r.randint(1, 999)}.{r.choice(['doc', 'pdf', 'zip'])}", "proj", bad=True)
                    if sc == 3:
                        if d + 1 < s0 + 3:
                            add("http", tm, u["user"], pc, f"http://www.{r.choice(HACK)}/download/keylogger.exe", "kl", bad=True)
                            add("device", tm, u["user"], pc, "Connect", bad=True)
                        elif d + 1 == s1:
                            sup = next(x for x in users if x["user"] == u["sup"])
                            ls = day + timedelta(hours=r.uniform(12, 14))
                            add("logon", ls, sup["user"], sup["pc"], "Logon", bad=True, who=u["user"])
                            for _ in range(20):
                                add("email", ls + timedelta(minutes=r.randint(1, 10)), sup["user"], sup["pc"], ";".join(f"{x['user'].lower()}@dtaa.com" for x in r.sample(users, 5)),
                                    "", "", f"{sup['user'].lower()}@dtaa.com", "5000", "0", "alarming", bad=True, who=u["user"])
                            add("logon", ls + timedelta(minutes=15), sup["user"], sup["pc"], "Logoff", bad=True, who=u["user"])
                if r.random() > 0.04:   # ~4% orphan logons (no logoff), as in the real data
                    add("logon", en, u["user"], pc, "Logoff", bad=bad_s)

    heads = {"logon": ["id", "date", "user", "pc", "activity"], "device": ["id", "date", "user", "pc", "activity"],
             "file": ["id", "date", "user", "pc", "filename", "content"],
             "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
             "http": None}   # r4.2 style variation: write http.csv without a header to test detection
    for k, rows in ev.items():
        rows.sort(key=lambda x: datetime.strptime(x[1], FMT))
        with open(data / f"{k}.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            if heads[k]:
                w.writerow(heads[k])
            w.writerows(rows)
    months = sorted({(t0 + timedelta(days=d)).strftime("%Y-%m") for d in range(a.days)})
    for mi, m in enumerate(months):
        with open(data / "LDAP" / f"{m}.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["employee_name", "user_id", "email", "role", "business_unit", "functional_unit", "department", "team", "supervisor"])
            for u in users:
                role = u["role"]
                if u is by_role["Engineer"][-1] and mi >= 2:
                    role = "Manager"   # a role change, to exercise monthly regrouping
                w.writerow([f"Name {u['user']}", u["user"], f"{u['user'].lower()}@dtaa.com", role, "1", u["fu"], u["dept"], "T1", u["sup"]])
    with open(ans / "insiders.csv", "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["dataset", "scenario", "details", "user", "start", "end"])
        for sc, u, s0, s1 in ins:
            det = f"r4.2-{sc}-{u['user']}.csv"
            (ans / f"r4.2-{sc}").mkdir(exist_ok=True)
            with open(ans / f"r4.2-{sc}" / det, "w", newline="") as f2:
                csv.writer(f2).writerows(mal.get(u["user"], []))
            w.writerow(["4.2", sc, det, u["user"], (t0 + timedelta(days=s0 - 1)).strftime(FMT), (t0 + timedelta(days=s1 - 1)).strftime(FMT)])
    print(f"wrote {sum(len(v) for v in ev.values()):,} events for {len(users)} users; "
          f"{sum(len(v) for v in mal.values())} malicious events for {len(ins)} insiders -> {out}")


if __name__ == "__main__":
    main()
