# -*- coding: utf-8 -*-
"""Logger level + warna + ring buffer untuk UI."""
import sys
import threading
import time
from .config import LOG_FILE, ensure_dirs

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; D = "\033[90m"; N = "\033[0m"; BO = "\033[1m"

LEVEL_COLOR = {"debug": D, "info": C, "ok": G, "warn": Y, "err": R, "crit": M}
_ring = []
_ring_lock = threading.Lock()


def col(text, c):
    return f"{c}{text}{N}"


def log(msg, level="info", module="core"):
    line = f"[{time.strftime('%H:%M:%S')}] {level.upper():5} {module}: {msg}"
    with _ring_lock:
        _ring.append(line)
        del _ring[:-500]
    ensure_dirs()
    try:
        with LOG_FILE.open("a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass
    if level in ("err", "crit", "warn", "ok"):
        print(f"{LEVEL_COLOR[level]}{msg}{N}", file=sys.stderr if level in ("err", "crit") else sys.stdout)


def tail(n=50):
    with _ring_lock:
        return list(_ring[-n:])
