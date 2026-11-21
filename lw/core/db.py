# -*- coding: utf-8 -*-
"""SQLite per-workspace: target, port, finding, kredensial, job, sesi, artefak."""
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(id INTEGER PRIMARY KEY, host TEXT, ip TEXT, kind TEXT,
  note TEXT, created REAL);
CREATE TABLE IF NOT EXISTS ports(id INTEGER PRIMARY KEY, target_id INTEGER, port INTEGER,
  proto TEXT, state TEXT, service TEXT, version TEXT, banner TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, target TEXT, title TEXT,
  severity TEXT, module TEXT, detail TEXT, evidence TEXT, created REAL);
CREATE TABLE IF NOT EXISTS creds(id INTEGER PRIMARY KEY, target TEXT, username TEXT,
  secret TEXT, kind TEXT, source TEXT, created REAL);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, job_id INTEGER, name TEXT,
  path TEXT, size INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, module TEXT, args TEXT, status TEXT,
  started REAL, ended REAL, rc INTEGER, summary TEXT);
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, kind TEXT, endpoint TEXT,
  pid INTEGER, status TEXT, started REAL, meta TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, level TEXT, module TEXT, msg TEXT);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, body TEXT, created REAL);
"""

SEVERITIES = ("info", "low", "medium", "high", "critical")


class DB:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.c = sqlite3.connect(self.path, check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        with self._lock:
            self.c.executescript(SCHEMA)
            self.c.commit()

    def _w(self, sql, args=()):
        with self._lock:
            cur = self.c.execute(sql, args)
            self.c.commit()
            return cur.lastrowid

    def q(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self.c.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.q(sql, args)
        return r[0] if r else None

    # --- penulisan
    def event(self, level, module, msg):
        self._w("INSERT INTO events(ts,level,module,msg) VALUES(?,?,?,?)",
                (time.time(), level, module, msg))

    def target(self, host, ip=None, kind="host", note=""):
        return self._w("INSERT INTO targets(host,ip,kind,note,created) VALUES(?,?,?,?,?)",
                       (host, ip, kind, note, time.time()))

    def port(self, target_id, port, proto="tcp", state="open", service="", version="", banner=""):
        return self._w("INSERT INTO ports(target_id,port,proto,state,service,version,banner)"
                       " VALUES(?,?,?,?,?,?,?)",
                       (target_id, port, proto, state, service, version, banner[:2000]))

    def finding(self, target, title, severity, module, detail="", evidence=""):
        sev = severity if severity in SEVERITIES else "info"
        return self._w("INSERT INTO findings(target,title,severity,module,detail,evidence,created)"
                       " VALUES(?,?,?,?,?,?,?)",
                       (target, title, sev, module, detail, evidence[:8000], time.time()))

    def cred(self, target, username, secret, kind="password", source=""):
        return self._w("INSERT INTO creds(target,username,secret,kind,source,created)"
                       " VALUES(?,?,?,?,?,?)",
                       (target, username, secret, kind, source, time.time()))

    def artifact(self, job_id, name, path, size):
        return self._w("INSERT INTO artifacts(job_id,name,path,size,created) VALUES(?,?,?,?,?)",
                       (job_id, name, str(path), size, time.time()))

    def job_start(self, module, args):
        return self._w("INSERT INTO jobs(module,args,status,started) VALUES(?,?,?,?)",
                       (module, args, "running", time.time()))

    def job_end(self, job_id, status, rc, summary=""):
        self._w("UPDATE jobs SET status=?,ended=?,rc=?,summary=? WHERE id=?",
                (status, time.time(), rc, summary[:4000], job_id))

    def session(self, kind, endpoint, pid=None, meta=""):
        return self._w("INSERT INTO sessions(kind,endpoint,pid,status,started,meta)"
                       " VALUES(?,?,?,?,?,?)", (kind, endpoint, pid, "open", time.time(), meta))

    def session_close(self, sid, status="closed"):
        self._w("UPDATE sessions SET status=? WHERE id=?", (status, sid))

    # --- pembacaan
    def findings(self, limit=200):
        return self.q("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,))

    def creds(self, limit=200):
        return self.q("SELECT * FROM creds ORDER BY id DESC LIMIT ?", (limit,))

    def severity_counts(self):
        rows = self.q("SELECT severity, COUNT(*) n FROM findings GROUP BY severity")
        counts = {s: 0 for s in SEVERITIES}
        for r in rows:
            counts[r["severity"]] = r["n"]
        return counts

    def stats(self):
        def n(t):
            r = self.one(f"SELECT COUNT(*) c FROM {t}")
            return r["c"] if r else 0
        return {"targets": n("targets"), "ports": n("ports"), "findings": n("findings"),
                "creds": n("creds"), "artifacts": n("artifacts"), "jobs": n("jobs"),
                "sessions": n("sessions")}
