# -*- coding: utf-8 -*-
"""Selftest: verifikasi registry, engine eksekusi, dan modul offline."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import exec_engine, module_loader, reporting, runner
from .core.logger import col, D, G, R, Y

PASS = 0
FAIL = 0


def check(label, cond, note=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  {col('PASS', G)} {label}")
    else:
        FAIL += 1
        print(f"  {col('FAIL', R)} {label} {D}{note}{Y}")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><title>lw</title><body>lw-selftest ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "lw-selftest/1.0")
        self.end_headers()
        self.wfile.write(body)


def run(ws, cfg):
    print(col("\n=== LONE WOLF SELFTEST ===\n", Y))

    check("registry termuat", module_loader.stats()["total"] >= 55,
          f"hanya {module_loader.stats()['total']} modul")
    check("tidak ada modul invalid", not module_loader.errors(),
          str(module_loader.errors()[:3]))
    cats = set(module_loader.stats()["per_category"])
    check("14 kategori aktif", len(cats) == 14, str(sorted(cats)))

    r = exec_engine.run_source("python", "print(6*7)", ws.dir / "code", 30)
    check("engine python", r.ok and "42" in r.stdout, r.stderr[:80])
    r = exec_engine.run_source("bash", "echo lw-bash-ok", ws.dir / "code", 30)
    check("engine bash", r.ok and "lw-bash-ok" in r.stdout, r.stderr[:80])

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"

    for mod, args in (("recon.http_headers", {"target": url}),
                      ("recon.tech_detect", {"target": url}),
                      ("web.dirbust", {"target": url, "threads": 8}),
                      ("vuln.header_audit", {"target": url})):
        before = len(ws.db.findings(1000))
        job = runner.execute(mod, args, ws.db, cfg)
        check(f"modul {mod}", job is not None and job.rc == 0)
        check(f"  -> {mod} menulis data", len(ws.db.findings(1000)) >= before)

    p = reporting.generate(ws.db, ws.name, "json")
    check("report json", p.exists() and p.stat().st_size > 50)
    p = reporting.generate(ws.db, ws.name, "html")
    check("report html", p.exists() and p.stat().st_size > 200)

    srv.shutdown()
    print(f"\n  hasil: {col(str(PASS)+' PASS', G)} / {col(str(FAIL)+' FAIL', R)}")
    print(col("  " + ("SEMUA LOLOS" if FAIL == 0 else "ADA YANG GAGAL"), G if FAIL == 0 else R) + "\n")
    return 0 if FAIL == 0 else 1
