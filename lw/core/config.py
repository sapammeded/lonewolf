# -*- coding: utf-8 -*-
"""Konfigurasi berlapis: default -> global -> workspace -> override modul."""
import json
import os
import threading
from pathlib import Path

ROOT = Path(os.environ.get("LW_HOME") or (Path.home() / ".lw"))
WS_ROOT = ROOT / "workspaces"
OUT_ROOT = ROOT / "out"
PLUGIN_DIR = ROOT / "plugins"
LOG_FILE = ROOT / "lw.log"

DEFAULTS = {
    "threads": 16,
    "timeout": 20,
    "max_jobs": 8,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) LW/3.0",
    "wordlist": "",
    "nmap_args": "-sT -Pn --open -T4",
    "redirect": "https://www.google.com",
    "duration": 0,
}

ENSURE = (ROOT, WS_ROOT, OUT_ROOT, PLUGIN_DIR, OUT_ROOT / "reports")


def ensure_dirs():
    for p in ENSURE:
        p.mkdir(parents=True, exist_ok=True)


class Config:
    def __init__(self, workspace=None):
        ensure_dirs()
        self._lock = threading.RLock()
        self.workspace = workspace
        self.data = dict(DEFAULTS)
        self.data.update(self._read(ROOT / "config.json"))
        if workspace:
            self.data.update(self._read(WS_ROOT / workspace / "config.json"))

    @staticmethod
    def _read(p: Path) -> dict:
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}

    def get(self, key, default=None):
        with self._lock:
            return self.data.get(key, default)

    def set(self, key, value, persist=True):
        with self._lock:
            self.data[key] = value
        if not persist:
            return
        target = (WS_ROOT / self.workspace / "config.json") if self.workspace else (ROOT / "config.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        cur = self._read(target)
        cur[key] = value
        target.write_text(json.dumps(cur, indent=2))
