# -*- coding: utf-8 -*-
"""Workspace: direktori + DB terisolasi per engagement."""
import json
import shutil
import time
from pathlib import Path

from .config import WS_ROOT, ensure_dirs
from .db import DB


class Workspace:
    def __init__(self, name):
        ensure_dirs()
        self.name = name
        self.dir = WS_ROOT / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = DB(self.dir / "data.db")
        meta = self.dir / "meta.json"
        if not meta.exists():
            meta.write_text(json.dumps({"name": name, "created": time.time()}, indent=2))
        self.meta = json.loads(meta.read_text())

    def touch(self, **kw):
        self.meta.update(kw)
        (self.dir / "meta.json").write_text(json.dumps(self.meta, indent=2))


def list_workspaces():
    ensure_dirs()
    out = []
    for d in sorted(WS_ROOT.iterdir()):
        if d.is_dir():
            db = d / "data.db"
            out.append({"name": d.name, "size": sum(f.stat().st_size for f in d.rglob("*") if f.is_file()),
                        "has_db": db.exists()})
    return out


def delete(name):
    d = WS_ROOT / name
    if d.is_dir():
        shutil.rmtree(d)
        return True
    return False


def current_marker():
    from .config import ROOT
    p = ROOT / "current_ws"
    return p.read_text().strip() if p.exists() else None


def set_current(name):
    from .config import ROOT
    (ROOT / "current_ws").write_text(name)
