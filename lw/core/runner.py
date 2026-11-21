# -*- coding: utf-8 -*-
"""Eksekusi modul: validasi, konteks, job, persistensi, error isolation."""
import shutil
import time
import traceback
from pathlib import Path

from . import deps, module_loader
from .config import OUT_ROOT, ensure_dirs
from .logger import col, G, R, Y, C, D, M

JOBS = None
SESSIONS = None


def init(max_jobs=8):
    global JOBS, SESSIONS
    from .job import JobManager
    from .session import SessionManager
    JOBS = JobManager(max_jobs)
    SESSIONS = SessionManager()


class Ctx:
    def __init__(self, meta, args, db, cfg, job):
        self.meta = meta
        self.args = dict(args)
        self.db = db
        self.cfg = cfg
        self.job = job
        self.name = meta["name"]
        self.started = time.time()

    # --- parameter
    def p(self, key):
        if key in self.args and self.args[key] not in (None, ""):
            return self.args[key]
        spec = self.meta.get("params", {}).get(key, {})
        if "default" in spec:
            return spec["default"]
        return self.cfg.get(key)

    def pi(self, key):
        v = self.p(key)
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def pb(self, key):
        v = self.p(key)
        return str(v).lower() in ("1", "true", "y", "yes", "on")

    # --- output
    @property
    def stopped(self):
        return self.job.cancel.is_set()

    def out(self, text="", color=None):
        text = str(text)
        print(col(text, color) if color else text)
        self.job.out(text)

    def log(self, msg, level="info"):
        self.db.event(level, self.name, msg)
        self.out(msg, {"err": R, "warn": Y, "ok": G, "info": C}.get(level))

    def sleep(self, sec, step=0.4):
        end = time.time() + sec
        while time.time() < end and not self.stopped:
            time.sleep(min(step, end - time.time()))

    # --- data
    def finding(self, title, severity="info", detail="", evidence=""):
        self.db.finding(self.p("target"), title, severity, self.name, detail, evidence)
        self.out(f"  [{severity.upper()}] {title}", {"critical": M, "high": R, "medium": Y}.get(severity, D))

    def cred(self, username, secret, kind="password", source=""):
        self.db.cred(self.p("target"), username, secret, kind, source or self.name)
        self.out(f"  [CRED] {username}:{secret}", G)

    def host(self, host, ip=None, kind="host", note=""):
        return self.db.target(host, ip, kind, note)

    def port(self, target_id, port, **kw):
        return self.db.port(target_id, port, **kw)

    def artifact(self, name, data, binary=False):
        ensure_dirs()
        d = OUT_ROOT / "artifacts" / str(int(time.time()))
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        if binary:
            p.write_bytes(data)
        else:
            p.write_text(data if isinstance(data, str) else str(data))
        self.db.artifact(self.job.id, name, p, p.stat().st_size)
        self.out(f"  [artifact] {p}", D)
        return p

    # --- eksekusi
    def exec(self, cmd, timeout=None, shell=None):
        import subprocess
        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(cmd) if shell else list(cmd)
            use_shell = False if shell is None else shell
        else:
            use_shell = True if shell is None else shell
        to = timeout or self.pi("timeout")
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=to,
                               shell=use_shell, errors="replace")
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"tidak ada: {cmd}"
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout {to}s"
        except Exception as e:
            return 1, "", str(e)

    def code(self, lang, source, timeout=120, argv=None):
        from . import exec_engine
        work = OUT_ROOT / "code" / str(self.job.id)
        r = exec_engine.run_source(lang, source, work, timeout, argv)
        self.out(r.text())
        return r

    def need(self, *tools):
        miss = deps.missing(tools)
        if miss:
            self.out(f"  [!] butuh: {', '.join(miss)}", Y)
            self.out(f"  [i] {deps.install_cmd(miss)}", C)
            return False
        return True


def _validate_args(meta, args):
    missing = []
    for key, spec in (meta.get("params") or {}).items():
        if spec.get("required") and args.get(key) in (None, ""):
            missing.append(key)
    return missing


def execute(module_name, args=None, db=None, cfg=None, bg=False, on_done=None):
    meta = module_loader.get(module_name)
    if not meta:
        print(col(f"[!] modul tidak ada: {module_name}", R))
        return None

    args = dict(args or {})
    miss = _validate_args(meta, args)
    if miss:
        print(col(f"[!] parameter wajib: {', '.join(miss)}", R))
        return None
    if meta.get("root") and not shutil.which("tsu") and not shutil.which("sudo"):
        print(col("[!] modul ini butuh root (tsu/sudo). Lanjut tanpa root.", Y))
    if meta.get("needs"):
        if not deps.missing(meta["needs"]):
            pass
        else:
            print(col(f"[i] tool kurang: {', '.join(deps.missing(meta['needs']))} "
                      f"-> {deps.install_cmd(meta['needs'])}", Y))

    def body(job):
        jid = db.job_start(meta["name"], str(args)) if db else None
        ctx = Ctx(meta, args, db, cfg, job)
        ctx.out(f"\n=== {meta['name']} :: {meta['desc']}", C)
        try:
            res = meta["run"](ctx)
            summary = "" if res is None else str(res)[:2000]
            if db and jid:
                db.job_end(jid, "done", 0, summary)
            return 0
        except KeyboardInterrupt:
            ctx.out("  [dibatalkan]", Y)
            if db and jid:
                db.job_end(jid, "cancelled", 130)
            return 130
        except Exception as e:
            ctx.out(f"  [!] error: {e}", R)
            ctx.out(traceback.format_exc(limit=3), D)
            if db and jid:
                db.job_end(jid, "error", 1, str(e))
            return 1

    if JOBS is None:
        init()
    job = JOBS.submit(meta["name"], args, body, on_done)
    if bg:
        print(col(f"[*] job #{job.id} jalan di latar. 'jobs' untuk status.", C))
        return job
    while job.status in ("queued", "running"):
        time.sleep(0.2)
    return job


def execute_sync(module_name, args=None, db=None, cfg=None):
    return execute(module_name, args, db, cfg, bg=False)


def parse_kv(pairs):
    out = {}
    for item in pairs:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k] = v
    return out
