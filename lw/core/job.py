# -*- coding: utf-8 -*-
"""Job manager: pool thread, pembatalan, persistensi."""
import threading
import time
from .config import ensure_dirs


class Job:
    def __init__(self, jid, module, args):
        self.id = jid
        self.module = module
        self.args = args
        self.status = "queued"
        self.started = time.time()
        self.ended = None
        self.rc = None
        self.summary = ""
        self.lines = []
        self.cancel = threading.Event()
        self._lock = threading.Lock()

    def out(self, text):
        with self._lock:
            self.lines.append(text)
            del self.lines[:-5000]

    def text(self):
        return "\n".join(self.lines)


class JobManager:
    def __init__(self, max_jobs=8):
        self.max_jobs = max_jobs
        self._jobs = {}
        self._next = 1
        self._lock = threading.Lock()
        self._sema = threading.Semaphore(max_jobs)

    def create(self, module, args):
        with self._lock:
            j = Job(self._next, module, args)
            self._jobs[j.id] = j
            self._next += 1
        return j

    def get(self, jid):
        return self._jobs.get(int(jid))

    def all(self):
        with self._lock:
            return list(self._jobs.values())

    def running(self):
        return [j for j in self.all() if j.status == "running"]

    def submit(self, module, args, fn, on_done=None):
        job = self.create(module, args)

        def wrap():
            with self._sema:
                job.status = "running"
                try:
                    rc = fn(job)
                    job.rc = 0 if rc is None else int(rc)
                    job.status = "done" if job.rc == 0 else "failed"
                except KeyboardInterrupt:
                    job.cancel.set()
                    job.status = "cancelled"
                    job.rc = 130
                except Exception as e:
                    job.rc = 1
                    job.status = "error"
                    job.summary = str(e)
                finally:
                    job.ended = time.time()
                    if on_done:
                        try:
                            on_done(job)
                        except Exception:
                            pass

        t = threading.Thread(target=wrap, daemon=True, name=f"job-{job.id}")
        t.start()
        return job

    def kill(self, jid):
        j = self.get(jid)
        if not j:
            return False
        j.cancel.set()
        if j.status in ("queued", "running"):
            j.status = "cancelling"
        return True

    def reap(self):
        with self._lock:
            done = [j for j in self._jobs.values() if j.status in ("done", "failed", "error", "cancelled")]
            for j in done:
                del self._jobs[j.id]
            return len(done)
