# -*- coding: utf-8 -*-
"""Reconnaissance & footprinting."""
import re

from ..core import netutil as nu
from ._base import MODULES, mod

SUBS = ["www", "mail", "api", "dev", "staging", "test", "admin", "vpn", "git",
        "cdn", "app", "m", "blog", "shop", "portal", "db", "ftp", "smtp", "ns1", "ns2"]


@mod(name="recon.whois", category="recon", desc="Whois lookup domain/IP",
     needs=["whois"], params={"target": {"required": True, "desc": "domain / IP"}})
def whois(ctx):
    rc, out, err = ctx.exec(["whois", ctx.p("target")], 45)
    ctx.out(out or err)
    for pat, label in ((r"Registrar:\s*(.+)", "registrar"), (r"Creation Date:\s*(.+)", "created"),
                       (r"Registry Expiry Date:\s*(.+)", "expiry")):
        m = re.search(pat, out, re.I)
        if m:
            ctx.finding(f"whois {label}", "info", m.group(1).strip())
    ctx.artifact("whois.txt", out)
    return f"{len(out)} byte whois"


@mod(name="recon.dns", category="recon", desc="Enumerasi record DNS",
     params={"target": {"required": True, "desc": "domain"}})
def dns(ctx):
    t = ctx.p("target")
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"):
        if nu.have("dig"):
            rc, out, err = ctx.exec(["dig", "+short", rtype, t], 15)
        else:
            out = "\n".join(nu.resolve(t)) if rtype == "A" else ""
        out = out.strip()
        ctx.out(f"  {rtype:5} -> {out or '-'}")
        if out:
            ctx.finding(f"DNS {rtype}", "info", out[:400])
    return "dns selesai"


@mod(name="recon.revdns", category="recon", desc="Reverse DNS / PTR",
     params={"target": {"required": True, "desc": "IP"}})
def revdns(ctx):
    name = nu.reverse(ctx.p("target"))
    ctx.out(f"  PTR: {name or 'tidak ada'}")
    if name:
        ctx.finding("reverse DNS", "info", name)
    return name


@mod(name="recon.http_headers", category="recon", desc="Ambil header HTTP mentah",
     params={"target": {"required": True, "desc": "host atau URL"}})
def http_headers(ctx):
    t = ctx.p("target")
    if not t.startswith("http"):
        t = "https://" + t
    status, headers, body = nu.http_get(t, ctx.pi("timeout"))
    ctx.out(f"  status {status}")
    for k, v in headers.items():
        ctx.out(f"  {k}: {v}")
    ctx.finding("header HTTP", "info", f"status {status}", "\n".join(f"{k}: {v}" for k, v in headers.items()))
    return f"status {status}"


@mod(name="recon.tech_detect", category="recon", desc="Deteksi teknologi web",
     params={"target": {"required": True, "desc": "host atau URL"}})
def tech_detect(ctx):
    t = ctx.p("target")
    if not t.startswith("http"):
        t = "http://" + t
    status, headers, body = nu.http_get(t, ctx.pi("timeout"))
    text = body.decode(errors="ignore").lower()[:300000]
    sigs = [("wp-content", "WordPress"), ("_next", "Next.js"), ("laravel", "Laravel"),
            ("csrf-token", "Laravel/CSRF"), ("drupal", "Drupal"), ("react", "React"),
            ("cloudflare", "Cloudflare"), ("shopify", "Shopify"), ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"), ("/graphql", "GraphQL")]
    hits = []
    for sig, tech in sigs:
        if sig in text:
            hits.append(tech)
            ctx.out(f"  {tech}")
    srv = headers.get("Server", "")
    if srv:
        hits.append(srv)
        ctx.out(f"  Server: {srv}")
    if hits:
        ctx.finding("teknologi terdeteksi", "low", ", ".join(hits))
    return hits


@mod(name="recon.crtsh", category="recon", desc="Subdomain via certificate transparency",
     params={"target": {"required": True, "desc": "domain"}})
def crtsh(ctx):
    t = ctx.p("target")
    import json
    status, _, body = nu.http_get(f"https://crt.sh/?q=%25.{t}&output=json", 45)
    try:
        rows = json.loads(body.decode(errors="ignore"))
    except Exception:
        ctx.out("  gagal parse crt.sh"); return None
    names = sorted({n.strip().lower() for r in rows for n in r.get("name_value", "").split("\n")
                    if n.strip().endswith(t)})
    for n in names:
        ctx.out(f"  {n}")
        ctx.finding("subdomain (crt.sh)", "info", n)
    ctx.artifact("crtsh.txt", "\n".join(names))
    return f"{len(names)} nama"


@mod(name="recon.subdomain", category="recon", desc="Bruteforce subdomain dari wordlist",
     params={"target": {"required": True, "desc": "domain"},
             "threads": {"default": 16}})
def subdomain(ctx):
    base = ctx.p("target")
    words = list(SUBS)
    wl = ctx.p("wordlist")
    if wl:
        try:
            words = [l.strip() for l in open(wl) if l.strip()][:5000]
        except Exception:
            pass
    found = nu.parallel(words, lambda w: (w, nu.resolve(f"{w}.{base}")) if nu.resolve(f"{w}.{base}") else None,
                        ctx.pi("threads"))
    for w, ips in found:
        ctx.out(f"  {w}.{base} -> {', '.join(ips)}")
        ctx.finding("subdomain aktif", "info", f"{w}.{base} -> {ips}")
    return f"{len(found)} ditemukan"


@mod(name="recon.asn", category="recon", desc="ASN + prefix owner dari IP",
     params={"target": {"required": True, "desc": "IP"}})
def asn(ctx):
    ip = ctx.p("target")
    rev = ".".join(reversed(ip.split(".")))
    if nu.have("dig"):
        rc, out, _ = ctx.exec(["dig", "+short", "TXT", f"{rev}.origin.asn.cymru.com"], 15)
        ctx.out(out.strip() or "  tidak ada data")
        if out.strip():
            ctx.finding("ASN", "info", out.strip())
    rc, out, _ = ctx.exec(["whois", ip], 30)
    for line in out.splitlines():
        if re.match(r"(?i)(netname|orgname|descr|country|route):", line):
            ctx.out("  " + line.strip())
    return "asn selesai"


@mod(name="recon.robots", category="recon", desc="robots.txt & sitemap.xml",
     params={"target": {"required": True, "desc": "host atau URL"}})
def robots(ctx):
    base = ctx.p("target").rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        status, _, body = nu.http_get(base + path, 12)
        if status == 200:
            text = body.decode(errors="ignore")[:4000]
            ctx.out(f"\n  [{status}] {path}\n{text}")
            ctx.finding(f"file terbuka {path}", "low", path, text)
        else:
            ctx.out(f"  [{status}] {path}")
    return "robots selesai"


@mod(name="recon.dork", category="recon", desc="Generator dork untuk target",
     params={"target": {"required": True, "desc": "domain"}})
def dork(ctx):
    t = ctx.p("target")
    dorks = [f'site:{t} ext:pdf', f'site:{t} inurl:admin', f'site:{t} intitle:index.of',
             f'site:{t} ext:sql OR ext:bak OR ext:env', f'site:{t} inurl:.git',
             f'"@{t}" password', f'site:{t} intext:"sql syntax near"']
    for d in dorks:
        ctx.out(f"  {d}")
        ctx.out(f"    https://duckduckgo.com/?q={d.replace(' ', '+').replace(':', '%3A')}")
    ctx.artifact("dorks.txt", "\n".join(dorks))
    return f"{len(dorks)} dork"
