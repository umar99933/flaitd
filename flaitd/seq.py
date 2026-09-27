"""Shared helpers for the sequence models: per-user standardisation, history windows, training loop."""
import copy

import numpy as np
import torch
import torch.nn as nn

from .log import log


def device_of(cfg_dev):
    if cfg_dev == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return cfg_dev


def set_seed(seed):
    np.random.seed(seed)
    torch.manual_seed(seed)


def per_user_standardise(df, X, fit_mask, floor, min_sd=0.1):
    """z = (x - mean_u) / max(std_u, floor * global_std, min_sd). Stats come from rows where fit_mask is True.

    `min_sd` (in model units, i.e. log1p for counts) keeps a rare feature from getting a near-zero scale:
    with sd ~ 1e-3 a single later keyword hit became z ~ 1000 and swamped the loss (CHANGES.md #4)."""
    g_mu = X[fit_mask].mean(0)
    g_sd = X[fit_mask].std(0)
    users = df["user"].to_numpy()
    mu = np.tile(g_mu, (len(df), 1)).astype(np.float32)
    sd = np.tile(g_sd, (len(df), 1)).astype(np.float32)
    fit_df = df.loc[fit_mask, ["user"]].copy()
    fit_df["_i"] = np.flatnonzero(fit_mask)
    for u, idx in fit_df.groupby("user")["_i"]:
        idx = idx.to_numpy()
        if len(idx) < 2:
            continue
        rows = users == u
        mu[rows] = X[idx].mean(0)
        sd[rows] = np.maximum(X[idx].std(0), floor * g_sd)
    sd = np.maximum(sd, min_sd)
    return ((X - mu) / sd).astype(np.float32), mu, sd


def history_index(df, w, include_current=False):
    """H[i] = global row indices of the w sessions before row i (same user), left-padded with -1.
    With include_current the window ends at row i itself. df must be sorted by user, start."""
    n = len(df)
    pos = df.groupby("user").cumcount().to_numpy()
    H = np.full((n, w), -1, dtype=np.int64)
    rows = np.arange(n)
    for k in range(1, w + 1):
        off = k - 1 if include_current else k
        col = w - k
        ok = pos >= off
        H[ok, col] = rows[ok] - off
    return H


def gather(Zp, H):
    """Zp is Z with an extra zero row appended; -1 in H picks that zero row."""
    return Zp[H]


class TemporalAttention(nn.Module):
    """Additive attention over time steps: u_k = v^T tanh(W h_k + b), alpha = softmax(u) over valid steps."""

    def __init__(self, hidden, attn_dim):
        super().__init__()
        self.W = nn.Linear(hidden, attn_dim)
        self.v = nn.Linear(attn_dim, 1, bias=False)

    def forward(self, Hs, mask):
        u = self.v(torch.tanh(self.W(Hs))).squeeze(-1)
        u = u.masked_fill(~mask, -1e9)
        a = torch.softmax(u, dim=1)
        return (a.unsqueeze(-1) * Hs).sum(1), a


def fit(model, make_batch, train_idx, val_idx, loss_fn, lr, batch_size, max_epochs, patience, dev, seed, name):
    """Generic mini-batch training with early stopping on validation loss; returns the best model."""
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    rng = np.random.default_rng(seed)
    best, best_state, bad = np.inf, None, 0
    for ep in range(max_epochs):
        model.train()
        perm = rng.permutation(train_idx)
        tot = 0.0
        for s in range(0, len(perm), batch_size):
            b = perm[s:s + batch_size]
            opt.zero_grad()
            loss = loss_fn(model, *make_batch(b))
            loss.backward()
            opt.step()
            tot += loss.item() * len(b)
        model.eval()
        with torch.no_grad():
            vl = 0.0
            for s in range(0, len(val_idx), 4096):
                b = val_idx[s:s + 4096]
                vl += loss_fn(model, *make_batch(b)).item() * len(b)
            vl /= max(len(val_idx), 1)
        log(f"{name}: epoch {ep + 1} train {tot / max(len(perm), 1):.4f} val {vl:.4f}")
        if vl < best - 1e-5:
            best, best_state, bad = vl, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
            if bad >= patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    return model
