import sys
import time

_T0 = time.time()


def log(msg):
    print(f"[{time.time() - _T0:8.1f}s] {msg}", file=sys.stderr, flush=True)
