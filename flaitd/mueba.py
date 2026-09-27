"""Reimplementation of MUEBA (Liu et al., ML4CS 2022) as a baseline.

Followed from the paper:  session units; its Table 2 features (numeric part); window of 10 sessions;
attention-based LSTM *classifier* trained on labelled sessions of the first 210 days; role groups
defined per month; a modified iForest per role group; final alert only if both parts flag the session.
Our reading where the paper is underspecified (see METHODOLOGY.md):
  * classifier label = label of the last session in the window; class-weighted BCE; fixed epochs;
  * iForest: per (role, month), fitted and scored on that month's sessions (in-group comparison);
    subsample with the most 3-sigma outliers of e = squared standardised distance to the group mean;
    split at the golden point of a random attribute (itree.IsoForest mode="mueba");
  * thresholds 0.5 for both parts (MUEBA Fig. 4 marks 0.5 as the anomaly boundary).
"""
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from . import seq
from .features import MUEBA_FEATURES, matrix
from .group import user_attributes
from .itree import IsoForest
from .log import log


class AttnClassifier(nn.Module):
    def __init__(self, d, hidden, attn_dim):
        super().__init__()
        self.lstm = nn.LSTM(d, hidden, batch_first=True)
        self.att = seq.TemporalAttention(hidden, attn_dim)
        self.out = nn.Linear(hidden, 1)

    def forward(self, xw, mask):
        Hs, _ = self.lstm(xw)
        c, a = self.att(Hs, mask)
        return self.out(c).squeeze(-1), a


def run_mueba(df, cfg, seed, feats=None):
    """`feats` defaults to MUEBA's Table 2 features; a subset is used for the keyword-free check."""
    mc = cfg["mueba"]
    seq.set_seed(seed)
    dev = seq.device_of(cfg["individual"]["device"])
    t0 = time.time()
    X = matrix(df, MUEBA_FEATURES if feats is None else feats)
    fit_rows = df["period"].isin(["train", "val"]).to_numpy()   # MUEBA: first 210 days for training and tuning
    mu, sd = X[fit_rows].mean(0), X[fit_rows].std(0) + 1e-6
    Z = ((X - mu) / sd).astype(np.float32)
    H = seq.history_index(df, mc["window"], include_current=True)
    Zt = torch.tensor(np.vstack([Z, np.zeros((1, Z.shape[1]), np.float32)])); Ht = torch.tensor(H)
    y = torch.tensor(df["mal"].to_numpy().astype(np.float32))
    npos = float(df.loc[fit_rows, "mal"].sum()); nneg = float(fit_rows.sum() - npos)
    pw = torch.tensor(min(nneg / max(npos, 1.0), 1000.0), device=dev)
    lossf = nn.BCEWithLogitsLoss(pos_weight=pw)

    def make_batch(b):
        hb = Ht[b]
        return Zt[hb].to(dev), (hb >= 0).to(dev), y[b].to(dev)

    def loss_fn(model, xw, mask, yy):
        logit, _ = model(xw, mask)
        return lossf(logit, yy)

    model = AttnClassifier(Z.shape[1], mc["hidden"], mc["attn_dim"]).to(dev)
    idx = np.flatnonzero(fit_rows)
    rng = np.random.default_rng(seed)
    mon = rng.choice(idx, min(len(idx), 5000), replace=False)   # monitoring only; no early stopping
    model = seq.fit(model, make_batch, idx, mon, loss_fn, cfg["individual"]["lr"], mc["batch_size"],
                    mc["epochs"], mc["epochs"] + 1, dev, seed, f"mueba_lstm(seed={seed})")
    p = np.zeros(len(df))
    with torch.no_grad():
        for s in range(0, len(df), 8192):
            b = np.arange(s, min(s + 8192, len(df)))
            xw, mask, _ = make_batch(b)
            p[b] = torch.sigmoid(model(xw, mask)[0]).cpu().numpy()
    t_lstm = time.time() - t0

    t1 = time.time()
    a = user_attributes(cfg, df)
    role = a.set_index(["month", "user"])["role"].reindex(pd.MultiIndex.from_arrays([df["month"], df["user"]])).to_numpy()
    sg = np.full(len(df), np.nan)
    Xr = X.astype(np.float64)
    for (r, m), rows in pd.DataFrame({"r": role, "m": df["month"].to_numpy()}).groupby(["r", "m"]).groups.items():
        rows = np.asarray(rows)
        if len(rows) < 2:
            sg[rows] = 0.5
            continue
        f = IsoForest(mc["n_trees"], mc["max_samples"], mode="mueba", seed=seed,
                      n_candidates=mc["n_candidates"], golden=mc["golden"]).fit(Xr[rows])
        sg[rows] = f.score(Xr[rows])
    t_if = time.time() - t1
    alert = (p > mc["threshold_lstm"]) & (sg > mc["threshold_iforest"])
    log(f"mueba seed={seed}: lstm {t_lstm:.0f}s, iforest {t_if:.0f}s, train positives {int(npos)}")
    return dict(p_lstm=p, s_iforest=sg, alert=alert, seconds=dict(lstm=t_lstm, iforest=t_if))
