"""NumPy isolation forests used where scikit-learn has no equivalent.

mode="eif"   Extended Isolation Forest (Hariri et al., 2021): random hyperplane splits.
mode="mueba" Our reading of MUEBA's modified iForest: each tree is built on the candidate subsample with
             the most 3-sigma outliers of a per-sample deviation e, and nodes split the chosen attribute at
             the golden-section point min + g*(max - min). MUEBA does not define e or the golden point
             precisely; see METHODOLOGY.md, section "MUEBA reimplementation".
"""
import numpy as np

EULER = 0.5772156649


def c_factor(n):
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + EULER) - 2.0 * (n[big] - 1.0) / n[big]
    out[n == 2] = 1.0
    return out


class _Tree:
    __slots__ = ("feat", "thr", "normal", "left", "right", "size", "leaf")

    def __init__(self):
        self.feat, self.thr, self.normal, self.left, self.right, self.size, self.leaf = [], [], [], [], [], [], []

    def add(self, leaf, size, feat=-1, thr=0.0, normal=None):
        self.feat.append(feat); self.thr.append(thr); self.normal.append(normal)
        self.left.append(-1); self.right.append(-1); self.size.append(size); self.leaf.append(leaf)
        return len(self.leaf) - 1


class IsoForest:
    def __init__(self, n_trees=100, max_samples=256, mode="eif", seed=0, n_candidates=5, golden=0.618):
        self.n_trees, self.max_samples, self.mode = n_trees, max_samples, mode
        self.rng = np.random.default_rng(seed)
        self.n_candidates, self.golden = n_candidates, golden

    # -------------------------------------------------------------- fitting
    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        n = len(X)
        self.psi = min(self.max_samples, n)
        self.limit = int(np.ceil(np.log2(max(self.psi, 2))))
        if self.mode == "mueba":
            mu, sd = X.mean(0), X.std(0) + 1e-9
            e = (((X - mu) / sd) ** 2).sum(1)           # deviation of each sample from the group
            lo, hi = e.mean() - 3 * e.std(), e.mean() + 3 * e.std()
            out3 = (e < lo) | (e > hi)
        self.trees = []
        for _ in range(self.n_trees):
            if self.mode == "mueba":
                cands = [self.rng.choice(n, self.psi, replace=False) for _ in range(self.n_candidates)]
                idx = max(cands, key=lambda c: out3[c].sum())
            else:
                idx = self.rng.choice(n, self.psi, replace=False)
            t = _Tree()
            self._grow(t, X[idx], 0)
            self.trees.append(t)
        return self

    def _grow(self, t, Xs, depth):
        n = len(Xs)
        if depth >= self.limit or n <= 1:
            return t.add(True, n)
        if self.mode == "eif":
            lo, hi = Xs.min(0), Xs.max(0)
            if np.all(hi - lo <= 0):
                return t.add(True, n)
            normal = self.rng.normal(size=Xs.shape[1])
            p = self.rng.uniform(lo, hi)
            go_left = (Xs - p) @ normal <= 0
            node = t.add(False, n, thr=float(p @ normal), normal=normal)
        else:
            spread = Xs.max(0) - Xs.min(0)
            cand = np.flatnonzero(spread > 0)
            if len(cand) == 0:
                return t.add(True, n)
            f = int(self.rng.choice(cand))
            lo, hi = Xs[:, f].min(), Xs[:, f].max()
            thr = lo + self.golden * (hi - lo)
            go_left = Xs[:, f] < thr
            node = t.add(False, n, feat=f, thr=float(thr))
        t.left[node] = self._grow(t, Xs[go_left], depth + 1)
        t.right[node] = self._grow(t, Xs[~go_left], depth + 1)
        return node

    # -------------------------------------------------------------- scoring
    def _path(self, t, X):
        path = np.zeros(len(X))
        stack = [(0, np.arange(len(X)), 0)]
        while stack:
            node, idx, depth = stack.pop()
            if len(idx) == 0:
                continue
            if t.leaf[node]:
                path[idx] = depth + c_factor([t.size[node]])[0]
                continue
            if t.normal[node] is not None:
                left = X[idx] @ t.normal[node] <= t.thr[node]
            else:
                left = X[idx, t.feat[node]] < t.thr[node]
            stack.append((t.left[node], idx[left], depth + 1))
            stack.append((t.right[node], idx[~left], depth + 1))
        return path

    def score(self, X):
        """Anomaly score s = 2^(-E[h(x)] / c(psi)) in (0, 1]; larger means more anomalous."""
        X = np.asarray(X, dtype=np.float64)
        E = np.mean([self._path(t, X) for t in self.trees], axis=0)
        return 2.0 ** (-E / c_factor([self.psi])[0])
