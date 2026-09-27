"""Individual branch (Section IV-B): attention-LSTM that predicts the next session from the user's last w sessions.

Score s^I_t = (1/d) * sum_j ((x_tj - xhat_tj) / sigma_j)^2, with sigma_j the residual std on validation sessions.
The per-feature terms give an exact attribution (residual shares). No insider labels are used except, when
clean_train is true, to drop known malicious sessions from the training targets.
"""
import time

import numpy as np
import torch
import torch.nn as nn

from . import seq
from .features import matrix
from .log import log


class Predictor(nn.Module):
    def __init__(self, d, hidden, attn_dim, attention=True):
        super().__init__()
        self.attention = attention
        self.lstm = nn.LSTM(d, hidden, batch_first=True)
        if attention:
            self.att = seq.TemporalAttention(hidden, attn_dim)
            self.out = nn.Linear(2 * hidden, d)
        else:
            self.out = nn.Linear(hidden, d)

    def forward(self, xw, mask):
        Hs, _ = self.lstm(xw)
        last = Hs[:, -1]
        if self.attention:
            c, a = self.att(Hs, mask)
            return self.out(torch.cat([c, last], 1)), a
        return self.out(last), None


def run_individual(df, cfg, feats, seed, attention=True, clean_train=None):
    """Train on the training period and score every session. Returns a dict of arrays."""
    ic = cfg["individual"]
    clean = ic["clean_train"] if clean_train is None else clean_train
    seq.set_seed(seed)
    if ic.get("num_threads"):
        torch.set_num_threads(ic["num_threads"])
    dev = seq.device_of(ic["device"])
    t0 = time.time()
    X = matrix(df, feats)
    is_train = (df["period"] == "train").to_numpy()
    is_val = (df["period"] == "val").to_numpy()
    fit_mask = is_train & ((df["mal"] == 0).to_numpy() if clean else True)
    Z, mu, sd = seq.per_user_standardise(df, X, fit_mask, ic["std_floor"], ic.get("min_std", 0.1))
    w = ic["window"]
    H = seq.history_index(df, w, include_current=False)
    Zp = np.vstack([Z, np.zeros((1, Z.shape[1]), np.float32)])
    Zt = torch.tensor(Zp)
    Ht = torch.tensor(H)
    tgt = torch.tensor(Z)

    def make_batch(b):
        hb = Ht[b]
        xw = Zt[hb].to(dev)
        mask = (hb >= 0).to(dev)
        mask[:, -1] = True  # always keep one step so attention is defined for a user's first session
        return xw, mask, tgt[b].to(dev)

    def loss_fn(model, xw, mask, y):
        pred, _ = model(xw, mask)
        return ((pred - y) ** 2).mean()

    model = Predictor(Z.shape[1], ic["hidden"], ic["attn_dim"], attention).to(dev)
    train_idx = np.flatnonzero(fit_mask)
    val_idx = np.flatnonzero(is_val)
    model = seq.fit(model, make_batch, train_idx, val_idx, loss_fn, ic["lr"], ic["batch_size"],
                    ic["max_epochs"], ic["patience"], dev, seed, f"individual(seed={seed},att={attention})")
    train_time = time.time() - t0

    t1 = time.time()
    pred = np.zeros_like(Z)
    attn = np.zeros((len(Z), w), dtype=np.float16)
    with torch.no_grad():
        for s in range(0, len(Z), 8192):
            b = np.arange(s, min(s + 8192, len(Z)))
            xw, mask, _ = make_batch(b)
            p, a = model(xw, mask)
            pred[b] = p.cpu().numpy()
            if a is not None:
                attn[b] = a.cpu().numpy().astype(np.float16)
    R = Z - pred
    sigma = R[is_val].std(0) + 1e-6 if is_val.any() else R.std(0) + 1e-6
    T = (R / sigma) ** 2
    score = T.mean(1)
    shares = (T / (T.sum(1, keepdims=True) + 1e-12)).astype(np.float16)
    log(f"individual seed={seed}: trained {train_time:.0f}s, scored {time.time() - t1:.0f}s")
    return dict(score=score.astype(np.float64), shares=shares, attn=attn, pred=pred, Z=Z, sigma=sigma,
                mu=mu, sd=sd, train_seconds=train_time, score_seconds=time.time() - t1)


def rescore_individual(res, df, feats, rows, X_new):
    """Recompute s^I for given rows after their raw feature vectors are replaced by X_new (deletion test)."""
    Zn = (X_new - res["mu"][rows]) / res["sd"][rows]
    T = ((Zn - res["pred"][rows]) / res["sigma"]) ** 2
    return T.mean(1)
