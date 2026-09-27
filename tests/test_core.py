import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import average_precision_score, roc_auc_score

from flaitd.fuzzy import FuzzyFusion
from flaitd.metrics import budget_threshold, _ap_weighted


def test_fuzzy_worked_examples():
    """Values quoted in the paper, Section IV-E."""
    ff = FuzzyFusion()
    r = ff.risk(np.array([0.99, 0.75, 0.5, 0.99]), np.array([0.5, 0.75, 0.5, 0.99]))
    assert r[0] == pytest.approx(0.500, abs=1e-3)
    assert r[1] == pytest.approx(0.372, abs=2e-3)
    assert r[2] == pytest.approx(0.082, abs=2e-3)
    assert r[3] == pytest.approx(0.918, abs=2e-3)
    assert list(ff.level(r)) == ["M", "L", "VL", "VH"]


def test_fuzzy_monotone_in_each_input():
    ff = FuzzyFusion(); g = np.linspace(0, 1, 41)
    for fixed in [0.1, 0.5, 0.9, 0.99]:
        assert np.all(np.diff(ff.risk(g, np.full_like(g, fixed))) >= -1e-9)


def test_proposition2_monotone_transform_keeps_curves():
    rng = np.random.default_rng(0)
    y = (rng.random(5000) < 0.01).astype(int); s = rng.random(5000) + y * 0.5
    mu = 1 / (1 + np.exp(-8 * (s - 0.6))); t = mu * s          # the earlier draft's Eq. 13
    assert average_precision_score(y, s) == pytest.approx(average_precision_score(y, t))
    assert roc_auc_score(y, s) == pytest.approx(roc_auc_score(y, t))


def test_proposition1_and_bounds_recall():
    rng = np.random.default_rng(1)
    y = (rng.random(10000) < 0.02).astype(bool)
    a = rng.random(10000) < 0.3; b = rng.random(10000) < 0.3
    a |= y & (rng.random(10000) < 0.7); b |= y & (rng.random(10000) < 0.6)
    rec = lambda m: (m & y).sum() / y.sum()
    assert rec(a & b) <= min(rec(a), rec(b))


def test_budget_threshold():
    v = np.arange(100.0)
    assert budget_threshold(v, n_val_days=10, per_day=1) == 90.0   # 10 alerts over 10 days


def test_weighted_ap_matches_sklearn_with_unit_weights():
    rng = np.random.default_rng(2)
    y = (rng.random(3000) < 0.05).astype(int); s = rng.random(3000) + y * 0.3
    o = np.argsort(-s, kind="stable")
    assert _ap_weighted(o, y, np.ones(len(y))) == pytest.approx(average_precision_score(y, s), abs=1e-9)


def test_session_pairing_and_orphan():
    from flaitd.sessions import _pair_logons
    t = pd.to_datetime
    lg = pd.DataFrame({"user": ["U"] * 4, "pc": ["P"] * 4,
                       "time": [t("2010-01-04 08:00"), t("2010-01-04 17:00"), t("2010-01-05 08:00"), t("2010-01-06 08:00")],
                       "act": [1, 0, 1, 1], "mal": [0, 0, 0, 0]})
    s = _pair_logons(lg, {})
    assert len(s) == 3
    assert bool(s["logoff_found"].iloc[0]) and not bool(s["logoff_found"].iloc[1])   # 2nd logon is an orphan
    assert s["next_logon"].iloc[1] == t("2010-01-06 08:00")


def test_same_day_relogon_is_screen_unlock():
    """r4.2 readme: screen unlocks are recorded as logons. A same-day repeat logon continues the session
    and passes its label on; a repeat logon on a later day is still an orphan."""
    from flaitd.sessions import _pair_logons
    t = pd.to_datetime
    lg = pd.DataFrame({"user": ["U"] * 5, "pc": ["P"] * 5,
                       "time": [t("2010-01-04 08:00"), t("2010-01-04 12:00"), t("2010-01-04 17:00"),
                                t("2010-01-05 08:00"), t("2010-01-06 08:00")],
                       "act": [1, 1, 0, 1, 1], "mal": [0, 3, 0, 0, 0]})
    s = _pair_logons(lg, {})
    assert len(s) == 3 and s.attrs["unlocks_merged"] == 1
    assert s["start"].iloc[0] == t("2010-01-04 08:00") and s["end"].iloc[0] == t("2010-01-04 17:00")
    assert s["mal_logon"].iloc[0] == 3
    assert not bool(s["logoff_found"].iloc[1])
    off = _pair_logons(lg, {"sessions": {"merge_unlocks": False}})
    assert len(off) == 4


def test_rare_feature_scale_is_floored():
    """A feature that (almost) never varies in the fitting rows must not explode when it later fires."""
    from flaitd.seq import per_user_standardise
    df = pd.DataFrame({"user": ["A"] * 4 + ["B"] * 4})
    X = np.array([[1, 0], [2, 0], [3, 0], [4, 0.693]] * 2, dtype=np.float32)
    fit = np.array([True, True, True, False] * 2)
    Z, mu, sd = per_user_standardise(df, X, fit, 0.1, min_sd=0.1)
    assert np.allclose(sd[:, 1], 0.1) and Z[3, 1] == pytest.approx(6.93, abs=1e-4)
    assert Z[0, 0] == pytest.approx((1 - 2) / np.std([1, 2, 3]), rel=1e-5)   # ordinary features unchanged
    X[0, 1] = 1e-4                                   # tiny non-zero spread (the not-cleaned case)
    Z, _, sd = per_user_standardise(df, X, fit, 0.1, min_sd=0.1)
    assert sd[:, 1].min() >= 0.1 and np.abs(Z[:, 1]).max() < 10


def test_keyword_hits_host_and_section_only():
    from flaitd.ingest import keyword_hits
    url = pd.Series(["http://monster.com/WboUhagvat1.html",            # job host
                     "http://aol.com/jobs/wbouhagvat1.jsp",            # job section
                     "http://craigslist.org/jobs/x.html",              # host + section
                     "http://craigslist.org/forsale/x.html",           # same host, other section
                     "http://cbssports.com/tagore/gitanjali/tbyspyhof1.asp",   # 'spy' only in filler
                     "http://lifehacker.com/enzyme/x.htm",             # excluded host
                     "http://www.actualkeylogger.com:8080/a"])         # host with port
    job = keyword_hits(url, ["monster.com", "/jobs", "craigslist.org/jobs"])
    assert list(job) == [True, True, True, False, False, False, False]
    hack = keyword_hits(url, ["hack", "spy", "keylog"], ["lifehacker.com"])
    assert list(hack) == [False, False, False, False, False, False, True]
