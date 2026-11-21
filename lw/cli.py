# -*- coding: utf-8 -*-
"""Entrypoint CLI: menu, console, run, list, doctor, selftest, report."""
import sys

from . import __version__
from .core import deps, module_loader, plugin_manager, reporting, runner
from .core.config import Config
from .core.logger import col, B, C, D, G, R, W, Y
from .core.workspace import Workspace, current_marker, list_workspaces, set_current

DEFAULT_WS = "default"


def _workspace(name=None):
    name = name or current_marker() or DEFAULT_WS
    set_current(name)
    return Workspace(name)


def usage():
    print(f"""
  LONE WOLF {__version__}

  python lonewolf.py                     menu
  python lonewolf.py console [--ws N]    console
  python lonewolf.py list [kategori]     daftar modul
  python lonewolf.py info <modul>        detail modul
  python lonewolf.py run <modul> k=v ..  eksekusi modul
  python lonewolf.py report <md|json|html>
  python lonewolf.py ws list|new|use N
  python lonewolf.py doctor              status dependensi
  python lonewolf.py selftest            verifikasi instalasi
  python lonewolf.py plugins             status plugin
""")


def main(argv):
    if not argv:
        from .ui.menu import run_menu
        ws = _workspace()
        runner.init(int(Config(ws.name).get("max_jobs")))
        plugin_manager.load_plugins()
        module_loader.load_all()
        try:
            run_menu(ws, Config(ws.name))
        finally:
            runner.SESSIONS.close_all()
        return 0

    cmd, rest = argv[0], argv[1:]

    if cmd in ("-h", "--help", "help"):
        usage()
        return 0
    if cmd in ("-v", "--version"):
        print(f"LONE WOLF {__version__}")
        return 0

    wsname = None
    if "--ws" in rest:
        i = rest.index("--ws")
        if i + 1 < len(rest):
            wsname = rest[i + 1]
            del rest[i:i + 2]
    ws = _workspace(wsname)
    cfg = Config(ws.name)
    runner.init(int(cfg.get("max_jobs")))
    plugin_manager.load_plugins()
    module_loader.load_all()

    if cmd == "console":
        from .core.console import Console
        try:
            Console(ws).loop()
        finally:
            runner.SESSIONS.close_all()
        return 0

    if cmd == "list":
        cat = rest[0] if rest else None
        for c, label in module_loader.CATEGORIES.items():
            if cat and c != cat:
                continue
            mods = module_loader.by_category(c)
            if not mods:
                continue
            print(col(f"\n[{c}] {label}", B))
            for m in mods:
                print(f"  {col(m['name'], C):<32} {D}{m['desc']}{W}")
        print(col(f"\ntotal: {module_loader.stats()['total']} modul", D))
        return 0

    if cmd == "info":
        m = module_loader.get(rest[0] if rest else "")
        if not m:
            print(col("modul tidak ada", R)); return 1
        print(f"{m['name']}\n  {m['desc']}\n  kategori: {m['category']}"
              f"\n  butuh: {', '.join(m.get('needs') or []) or '-'}"
              f"\n  root: {'ya' if m.get('root') else 'tidak'}")
        for k, s in (m.get("params") or {}).items():
            print(f"  param {k}: {s.get('desc','')} {'(wajib)' if s.get('required') else ''}")
        return 0

    if cmd == "run":
        if not rest:
            print(col("modul mana?", R)); return 1
        job = runner.execute(rest[0], runner.parse_kv(rest[1:]), ws.db, cfg)
        return 0 if job and job.rc == 0 else 1

    if cmd == "report":
        print(reporting.generate(ws.db, ws.name, rest[0] if rest else "md"))
        return 0

    if cmd == "ws":
        sub = rest[0] if rest else "list"
        if sub == "list":
            for w in list_workspaces():
                print(f"  {w['name']:<24} {w['size']} B")
        elif sub == "new":
            print(Workspace(rest[1]).dir)
        elif sub == "use":
            set_current(rest[1]); print(f"aktif: {rest[1]}")
        return 0

    if cmd == "doctor":
        for tool, ok, pkg in deps.doctor():
            print(f"  {col('OK  ' if ok else 'MISS', G if ok else R)} {tool:<22} {D}{pkg}{W}")
        print(col(f"\nterpasang: {sum(1 for _, ok, _ in deps.doctor() if ok)}"
                  f"/{len(deps.TOOLS)}", D))
        return 0

    if cmd == "plugins":
        for name, res in plugin_manager.load_plugins():
            print(f"  {name}: {res}")
        return 0

    if cmd == "selftest":
        from .selftest import run
        return run(ws, cfg)

    usage()
    return 1
