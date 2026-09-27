"""Mamdani fuzzy fusion (Section IV-E), vectorised over sessions.

Inputs are percentile scores in [0, 1]. Each input has Low / Medium / High terms; the output risk has
five triangular terms VL..VH. Rules use min for AND, consequents are clipped and aggregated with max,
and the risk is the centroid of the aggregated set on a fixed grid.
"""
import numpy as np

IN_TERMS = ["L", "M", "H"]
OUT_TERMS = ["VL", "L", "M", "H", "VH"]
OUT_CENTRES = [0.0, 0.25, 0.5, 0.75, 1.0]
RULES = {("L", "L"): "VL", ("L", "M"): "L", ("L", "H"): "M",
         ("M", "L"): "L", ("M", "M"): "M", ("M", "H"): "H",
         ("H", "L"): "M", ("H", "M"): "H", ("H", "H"): "VH"}


def trap(x, a, b, c, d):
    x = np.asarray(x, dtype=np.float64)
    y = np.zeros_like(x)
    y[(x >= b) & (x <= c)] = 1.0
    if b > a:
        m = (x > a) & (x < b); y[m] = (x[m] - a) / (b - a)
    if d > c:
        m = (x > c) & (x < d); y[m] = (d - x[m]) / (d - c)
    return y


class FuzzyFusion:
    def __init__(self, low_top=0.60, medium_peak=0.85, high_full=0.97, grid_points=201, rules=None):
        self.p = dict(low_top=low_top, medium_peak=medium_peak, high_full=high_full)
        self.inp = {"L": (0.0, 0.0, low_top, medium_peak),
                    "M": (low_top, medium_peak, medium_peak, high_full),
                    "H": (medium_peak, high_full, 1.0, 1.0)}
        self.y = np.linspace(0.0, 1.0, grid_points)
        self.out = {}
        for t, c in zip(OUT_TERMS, OUT_CENTRES):
            self.out[t] = trap(self.y, max(c - 0.25, 0) if c > 0 else 0, c, c, min(c + 0.25, 1) if c < 1 else 1)
        self.rules = rules or RULES

    @classmethod
    def from_cfg(cls, fc, **over):
        kw = dict(low_top=fc["low_top"], medium_peak=fc["medium_peak"], high_full=fc["high_full"], grid_points=fc["grid_points"])
        kw.update(over)
        return cls(**kw)

    def memberships(self, s):
        return {t: trap(s, *self.inp[t]) for t in IN_TERMS}

    def strengths(self, sI, sG):
        mI, mG = self.memberships(sI), self.memberships(sG)
        return {k: np.minimum(mI[k[0]], mG[k[1]]) for k in self.rules}

    def risk(self, sI, sG, chunk=50000):
        sI = np.clip(np.asarray(sI, float), 0, 1); sG = np.clip(np.asarray(sG, float), 0, 1)
        r = np.empty(len(sI))
        for s in range(0, len(sI), chunk):
            w = self.strengths(sI[s:s + chunk], sG[s:s + chunk])
            agg = np.zeros((len(sI[s:s + chunk]), len(self.y)))
            for k, wk in w.items():
                np.maximum(agg, np.minimum(wk[:, None], self.out[self.rules[k]][None, :]), out=agg)
            den = agg.sum(1)
            r[s:s + chunk] = np.where(den > 0, (agg * self.y).sum(1) / np.maximum(den, 1e-12), 0.0)
        return r

    def level(self, r):
        r = np.asarray(r, float)
        mem = np.stack([trap(r, max(c - 0.25, 0) if c > 0 else 0, c, c, min(c + 0.25, 1) if c < 1 else 1)
                        for c in OUT_CENTRES], 1)
        return np.array(OUT_TERMS)[mem.argmax(1)]

    def trace(self, sI, sG):
        """Fired rules for one session, strongest first: list of (I-term, G-term, output, strength)."""
        w = self.strengths(np.array([sI]), np.array([sG]))
        fired = [(k[0], k[1], self.rules[k], float(v[0])) for k, v in w.items() if v[0] > 0]
        return sorted(fired, key=lambda t: -t[3])


def ecdf_normaliser(ref):
    ref = np.sort(np.asarray(ref, float)[~np.isnan(ref)])
    def f(x):
        x = np.asarray(x, float)
        out = np.searchsorted(ref, x, side="right") / max(len(ref), 1)
        out[np.isnan(x)] = 0.5
        return out
    return f


def minmax_normaliser(ref):
    ref = np.asarray(ref, float); lo, hi = np.nanmin(ref), np.nanmax(ref)
    def f(x):
        x = np.asarray(x, float)
        out = np.clip((x - lo) / max(hi - lo, 1e-12), 0, 1)
        out[np.isnan(x)] = 0.5
        return out
    return f
