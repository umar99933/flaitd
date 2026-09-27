"""Evaluation: PR-AUC, ROC-AUC, alert-budget metrics, user-level detection and user bootstrap."""
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def budget_threshold(val_scores, n_val_days, per_day):
    """Threshold such that on average `per_day` validation sessions per day are at or above it."""
    v = np.sort(np.asarray(val_scores, float)[~np.isnan(val_scores)])[::-1]
    k = int(round(per_day * n_val_days))
    if k <= 0:
        return np.inf
    if k >= len(v):
        return -np.inf
    return v[k - 1]


def point_metrics(alert, y):
    tp = int((alert & (y == 1)).sum()); fp = int((alert & (y == 0)).sum()); fn = int((~alert & (y == 1)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return dict(precision=p, recall=r, f1=f1, tp=tp, fp=fp, fn=fn, alerts=int(alert.sum()))


def user_metrics(alert, y, users, owner, owner_scenario, insider):
    """Insiders with >=1 alerted malicious session (credited to the owning insider); benign users with >=1
    alert on a benign session; per-scenario counts."""
    active = set(owner[y == 1])
    found = set(owner[alert & (y == 1)])
    benign_alerted = set(users[alert & (y == 0) & (insider == 0)])
    out = dict(insiders_active=len(active), insiders_detected=len(found), benign_users_alerted=len(benign_alerted))
    scen_of = {u: s for u, s in zip(owner[y == 1], owner_scenario[y == 1])}
    for s in sorted({scen_of[u] for u in active}):
        out[f"sc{s}_active"] = sum(1 for u in active if scen_of[u] == s)
        out[f"sc{s}_detected"] = sum(1 for u in found if scen_of[u] == s)
    return out


def evaluate(test, y, score=None, alert=None, tau=None):
    """test: DataFrame of test sessions (user, scenario, insider). Either score+tau or a binary alert."""
    res = {}
    if score is not None:
        score = np.nan_to_num(np.asarray(score, float), nan=np.nanmin(score) if np.isfinite(np.nanmin(score)) else 0)
        if 0 < y.sum() < len(y):
            res["pr_auc"] = float(average_precision_score(y, score))
            res["roc_auc"] = float(roc_auc_score(y, score))
        alert = score >= tau
    res.update(point_metrics(alert, y))
    res.update(user_metrics(alert, y, test["user"].to_numpy(), test["owner"].to_numpy(),
                            test["owner_scenario"].to_numpy(), test["insider"].to_numpy()))
    return res


def _ap_weighted(order, y, w):
    yo, wo = y[order], w[order]
    cw = np.cumsum(wo); ctp = np.cumsum(wo * yo)
    pos = (yo == 1) & (wo > 0)
    tot = ctp[-1]
    if tot <= 0:
        return np.nan
    return float(np.sum(wo[pos] * (ctp[pos] / cw[pos])) / tot)


def bootstrap_ap_diff(score_a, score_b, y, users, n=1000, seed=0):
    """Paired bootstrap over users: CI for AP(a) - AP(b)."""
    rng = np.random.default_rng(seed)
    uniq, uidx = np.unique(users, return_inverse=True)
    oa = np.argsort(-np.asarray(score_a, float), kind="stable")
    ob = np.argsort(-np.asarray(score_b, float), kind="stable")
    diffs = []
    for _ in range(n):
        cnt = rng.multinomial(len(uniq), np.full(len(uniq), 1 / len(uniq)))
        w = cnt[uidx].astype(float)
        a, b = _ap_weighted(oa, y, w), _ap_weighted(ob, y, w)
        if np.isfinite(a) and np.isfinite(b):
            diffs.append(a - b)
    d = np.array(diffs)
    return dict(mean=float(d.mean()), lo=float(np.percentile(d, 2.5)), hi=float(np.percentile(d, 97.5)),
                p_le_0=float((d <= 0).mean()))
