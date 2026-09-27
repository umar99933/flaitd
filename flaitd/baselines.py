"""Single-view baselines: pooled OCSVM, LOF and Isolation Forest, and an LSTM autoencoder."""
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from . import seq
from .features import matrix
from .log import log


def run_classic(df, cfg, feats, seed):
    """Fit on (clean) training sessions, score validation and test sessions. Returns {name: scores}."""
    bc = cfg["baselines"]
    X = matrix(df, feats)
    tr = (df["period"] == "train").to_numpy().copy()
    if cfg["individual"]["clean_train"]:
        tr = tr & (df["mal"] == 0).to_numpy()
    rng = np.random.default_rng(seed)
    idx = np.flatnonzero(tr)
    if len(idx) > bc["fit_subsample"]:
        idx = rng.choice(idx, bc["fit_subsample"], replace=False)
    sc = StandardScaler().fit(X[idx])
    Xs = sc.transform(X)
    ev = np.flatnonzero(df["period"].isin(["val", "test"]).to_numpy())
    out, secs = {}, {}
    models = {
        "OCSVM": OneClassSVM(kernel="rbf", nu=bc["ocsvm_nu"], gamma="scale"),
        "LOF": LocalOutlierFactor(n_neighbors=bc["lof_k"], novelty=True),
        "iForest (pooled)": IsolationForest(n_estimators=100, max_samples=256, random_state=seed),
    }
    for name, m in models.items():
        t0 = time.time()
        m.fit(Xs[idx])
        s = np.full(len(df), np.nan)
        s[ev] = -m.score_samples(Xs[ev])
        out[name] = s; secs[name] = time.time() - t0
        log(f"baseline {name} seed={seed}: {secs[name]:.0f}s")
    return out, secs


class LSTMAE(nn.Module):
    def __init__(self, d, hidden):
        super().__init__()
        self.enc = nn.LSTM(d, hidden, batch_first=True)
        self.dec = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, d)

    def forward(self, xw):
        _, (h, _) = self.enc(xw)
        rep = h[-1].unsqueeze(1).repeat(1, xw.shape[1], 1)
        y, _ = self.dec(rep)
        return self.out(y)


def run_lstm_ae(df, cfg, feats, seed):
    ic = cfg["individual"]
    seq.set_seed(seed)
    dev = seq.device_of(ic["device"])
    t0 = time.time()
    X = matrix(df, feats)
    tr = (df["period"] == "train").to_numpy()
    fit_mask = tr & ((df["mal"] == 0).to_numpy() if ic["clean_train"] else True)
    Z, _, _ = seq.per_user_standardise(df, X, fit_mask, ic["std_floor"], ic.get("min_std", 0.1))
    w = ic["window"]
    H = seq.history_index(df, w, include_current=True)
    Zt = torch.tensor(np.vstack([Z, np.zeros((1, Z.shape[1]), np.float32)])); Ht = torch.tensor(H)

    def make_batch(b):
        hb = Ht[b]
        return Zt[hb].to(dev), (hb >= 0).to(dev)

    def loss_fn(model, xw, mask):
        err = ((model(xw) - xw) ** 2).mean(-1)
        return (err * mask).sum() / mask.sum()

    model = LSTMAE(Z.shape[1], ic["hidden"]).to(dev)
    model = seq.fit(model, make_batch, np.flatnonzero(fit_mask), np.flatnonzero((df["period"] == "val").to_numpy()),
                    loss_fn, ic["lr"], ic["batch_size"], ic["max_epochs"], ic["patience"], dev, seed, f"lstm_ae(seed={seed})")
    R = np.zeros_like(Z)
    with torch.no_grad():
        for s in range(0, len(Z), 8192):
            b = np.arange(s, min(s + 8192, len(Z)))
            xw, _ = make_batch(b)
            R[b] = (model(xw)[:, -1] - xw[:, -1]).cpu().numpy()
    val = (df["period"] == "val").to_numpy()
    sigma = R[val].std(0) + 1e-6 if val.any() else R.std(0) + 1e-6
    score = ((R / sigma) ** 2).mean(1)
    return score, time.time() - t0
