# -*- coding: utf-8 -*-
"""Command console interaktif."""
import os
import shlex

from . import deps, module_loader, reporting, runner
from .config import Config
from .logger import col, B, C, D, G, M, R, W, Y
from .workspace import Workspace

HELP = """
  use <modul>          pilih modul
  options              tampilkan parameter
  set <k> <v>          isi parameter
  unset <k>            hapus parameter
  run | run!           eksekusi (run! = latar)
  modules [kategori]   daftar modul
  search <kata>        cari modul
  info <modul>         detail modul
  jobs | kill <id>     kelola job
  sessions             sesi aktif
  workspace <nama>     pindah workspace
  findings | creds     hasil terkumpul
  report <md|json|html>
  exec <bahasa> <file|->  jalankan kode
  doctor               status dependensi
  target <host>        set target
  help | quit
"""


class Console:
    def __init__(self, ws: Workspace):
        self.ws = ws
        self.cfg = Config(ws.name)
        self.module = None
        self.args = {}

    def prompt(self):
        tgt = self.args.get("target") or "-"
        name = self.module or "lw"
        return f"{col(name, M)}@{col(self.ws.name, Y)}:{col(tgt, C)}> "

    def loop(self):
        print(col("\n[*] console aktif. 'help' untuk perintah.\n", D))
        while True:
            try:
                line = input(self.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not line:
                continue
            try:
                if self.dispatch(line):
                    return
            except KeyboardInterrupt:
                print(col("  dibatalkan", Y))
            except Exception as e:
                print(col(f"  [!] {e}", R))

    def dispatch(self, line):
        parts = line.split()
        cmd, rest = parts[0].lower(), parts[1:]

        if cmd in ("quit", "exit", "q"):
            return True
        if cmd == "help":
            print(HELP)
        elif cmd == "use":
            if not rest:
                print(col("  use <modul>", Y)); return
            meta = module_loader.get(rest[0])
            if not meta:
                cand = module_loader.search(rest[0])
                print(col(f"  tidak ada. mirip: {[c['name'] for c in cand[:6]]}", Y))
                return
            self.module = meta["name"]
            self.args = {"target": self.args.get("target")} if self.args.get("target") else {}
            print(col(f"  modul: {meta['name']} — {meta['desc']}", G))
            print(col(f"  {meta['source']}", D))
        elif cmd == "back":
            self.module = None
        elif cmd == "options":
            if not self.module:
                print(col("  belum ada modul", Y)); return
            meta = module_loader.get(self.module)
            for k, spec in (meta.get("params") or {}).items():
                cur = self.args.get(k) or spec.get("default") or self.cfg.get(k) or ""
                print(f"  {col(k, C):<22} {'WAJIB ' if spec.get('required') else ''}{cur}")
        elif cmd == "set":
            if len(rest) < 2:
                print(col("  set <k> <v>", Y)); return
            self.args[rest[0]] = " ".join(rest[1:])
        elif cmd == "unset":
            self.args.pop(rest[0] if rest else "", None)
        elif cmd == "target":
            if rest:
                self.args["target"] = rest[0]
                print(col(f"  target: {rest[0]}", G))
        elif cmd in ("run", "run!"):
            if not self.module:
                print(col("  pilih modul dulu", Y)); return
            runner.execute(self.module, self.args, self.ws.db, self.cfg, bg=(cmd == "run!"))
        elif cmd == "modules":
            cat = rest[0] if rest else None
            for c, label in module_loader.CATEGORIES.items():
                if cat and cat != c:
                    continue
                mods = module_loader.by_category(c)
                if not mods:
                    continue
                print(col(f"\n[{c}] {label}", B))
                for m in mods:
                    print(f"  {col(m['name'], C):<34} {D}{m['desc']}{W}")
        elif cmd == "search":
            for m in module_loader.search(" ".join(rest)):
                print(f"  {col(m['name'], C):<34} {D}{m['desc']}{W}")
        elif cmd == "info":
            m = module_loader.get(rest[0] if rest else "")
            if not m:
                print(col("  tidak ada", Y)); return
            print(f"  {m['name']} — {m['desc']}\n  kategori: {m['category']}\n"
                  f"  butuh: {', '.join(m.get('needs') or []) or '-'}\n"
                  f"  root: {'ya' if m.get('root') else 'tidak'}")
        elif cmd == "jobs":
            for j in runner.JOBS.all():
                print(f"  #{j.id} {j.status:<10} {j.module} {D}{time_since(j.started)}{W}")
        elif cmd == "kill":
            print(col("  dihentikan" if rest and runner.JOBS.kill(rest[0]) else "  id salah", Y))
        elif cmd == "sessions":
            for s in runner.SESSIONS.all():
                print(f"  #{s.id} {s.kind} {s.endpoint} pid={s.pid} {s.status}")
        elif cmd == "workspace":
            if not rest:
                print(col(f"  aktif: {self.ws.name}", G)); return
            from .workspace import set_current
            self.ws = Workspace(rest[0])
            self.cfg = Config(self.ws.name)
            set_current(rest[0])
            print(col(f"  pindah ke workspace: {rest[0]}", G))
        elif cmd == "findings":
            for f in self.ws.db.findings(60):
                print(f"  [{f['severity']}] {f['title']} — {f['target']} ({f['module']})")
        elif cmd == "creds":
            for c in self.ws.db.creds(60):
                print(f"  {c['target']} {c['username']}:{c['secret']}")
        elif cmd == "report":
            p = reporting.generate(self.ws.db, self.ws.name, rest[0] if rest else "md")
            print(col(f"  {p}", G))
        elif cmd == "exec":
            self.do_exec(rest)
        elif cmd == "doctor":
            for tool, ok, pkg in deps.doctor():
                print(f"  {'OK  ' if ok else 'MISS'} {tool:<22} {D}{pkg}{W}")
        else:
            print(col(f"  perintah tidak dikenal: {cmd}", R))
        return False

    def do_exec(self, rest):
        if not rest:
            print(col("  exec <bahasa> <file|->", Y)); return
        lang = rest[0]
        from . import exec_engine
        if lang not in exec_engine.LANGS:
            print(col(f"  bahasa: {', '.join(exec_engine.LANGS)}", Y)); return
        src = None
        if len(rest) > 1 and rest[1] != "-":
            src = open(rest[1]).read()
        else:
            print(col("  tempel kode, akhiri dengan baris 'EOF'", D))
            buf = []
            while True:
                l = input()
                if l.strip() == "EOF":
                    break
                buf.append(l)
            src = "\n".join(buf)
        r = exec_engine.run_source(lang, src, self.ws.dir / "code")
        print(r.text())


def time_since(t):
    import time
    d = int(time.time() - t)
    return f"{d}s" if d < 60 else f"{d // 60}m"
