# -*- coding: utf-8 -*-
"""Session manager untuk proses latar (listener, proxy, agent)."""
import os
import signal
import socket
import subprocess
import threading
import time


class Session:
    def __init__(self, sid, kind, endpoint, pid=None, proc=None):
        self.id = sid
        self.kind = kind
        self.endpoint = endpoint
        self.pid = pid
        self.proc = proc
        self.status = "open"
        self.started = time.time()
        self.meta = {}


class SessionManager:
    def __init__(self):
        self._s = {}
        self._next = 1
        self._lock = threading.Lock()

    def add(self, kind, endpoint, pid=None, proc=None, meta=None):
        with self._lock:
            s = Session(self._next, kind, endpoint, pid, proc)
            s.meta = meta or {}
            self._s[s.id] = s
            self._next += 1
        return s

    def get(self, sid):
        return self._s.get(int(sid))

    def all(self):
        return list(self._s.values())

    def close(self, sid, kill=True):
        s = self.get(sid)
        if not s:
            return False
        if kill:
            try:
                if s.proc:
                    s.proc.terminate()
                elif s.pid:
                    os.kill(s.pid, signal.SIGTERM)
            except Exception:
                pass
        s.status = "closed"
        return True

    def close_all(self):
        for s in self.all():
            self.close(s.id)


def port_free(port, host="0.0.0.0"):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def spawn(cmd, shell=False):
    return subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
