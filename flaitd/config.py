import copy
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path=None, overrides=None):
    """Load config/default.yaml, then an optional experiment file (which may set `base:`), then overrides."""
    cfg = yaml.safe_load(open(ROOT / "config" / "default.yaml"))
    if path:
        exp = yaml.safe_load(open(path)) or {}
        base = exp.pop("base", None)
        if base:
            cfg = _merge(cfg, yaml.safe_load(open(ROOT / "config" / base)))
        cfg = _merge(cfg, exp)
    cfg = _merge(cfg, overrides or {})
    for k in ("data_dir", "answers_dir", "cache_dir", "results_dir"):
        p = Path(cfg[k])
        cfg[k] = str(p if p.is_absolute() else ROOT / p)
    return cfg
