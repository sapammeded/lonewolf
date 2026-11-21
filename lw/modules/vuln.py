# -*- coding: utf-8 -*-
"""Vulnerability assessment."""
import json
import re

from ..core import netutil as nu
from ._base import MODULES, mod

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd(ctx, query):
    status, _, body = nu.http_get(f"{NVD}?{query}&resultsPerPage=20", 45)
    try:
        data = json.loads(body.decode(errors="ignore"))
    except Exception:
        ctx.out("  gagal baca NVD"); return []
    rows = []
    for item in data.get("vulnerabilities", []):
        c = item["cve"]
        score = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(key):
                score = float(c["metrics"][key][0]["cvssData"]["baseScore"]); break
        desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
        rows.append((c["id"], score, desc))
    return rows


def _emit(ctx, rows):
    for cid, score, desc in rows:
        sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
        ctx.out(f"  {cid} score={score} {desc[:150]}")
        ctx.finding(cid, sev, desc[:300], f"CVSS {score}")
    return f"{len(rows)} CVE"


@mod(name="vuln.cve", category="vuln", desc="Pencarian CVE via NVD API",
     params={"target": {"required": True, "desc": "keyword produk/versi"}})
def cve(ctx):
    rows = _nvd(ctx, "keywordSearch=" + nu.urllib.parse.quote(ctx.p("target")))
    if not rows:
        ctx.out("  tidak ada hasil")
    return _emit(ctx, rows)


@mod(name="vuln.cve_cpe", category="vuln", desc="CVE via CPE (vendor:produk:versi)",
     params={"target": {"required": True, "desc": "mis. apache:http_server:2.4.49"}})
def cve_cpe(ctx):
    rows = _nvd(ctx, "virtualMatchString=cpe:2.3:a:" + ctx.p("target"))
    return _emit(ctx, rows)


@mod(name="vuln.header_audit", category="vuln", desc="Audit header keamanan HTTP",
     params={"target": {"required": True, "desc": "host / URL"}})
def header_audit(ctx):
    t = ctx.p("target")
    if not t.startswith("http"):
        t = "https://" + t
    status, headers, _ = nu.http_get(t, ctx.pi("timeout"))
    low = {k.lower(): v for k, v in headers.items()}
    ctx.out(f"  status {status}")
    checks = [("strict-transport-security", "high", "tanpa HSTS"),
              ("content-security-policy", "medium", "tanpa CSP"),
              ("x-frame-options", "medium", "rawan clickjacking"),
              ("x-content-type-options", "low", "tanpa nosniff"),
              ("referrer-policy", "low", "tanpa referrer policy"),
              ("permissions-policy", "low", "tanpa permissions policy")]
    for h, sev, msg in checks:
        if h not in low:
            ctx.out(f"  [!] {msg}")
            ctx.finding(msg, sev, f"header {h} tidak ada")
        else:
            ctx.out(f"  ok  {h}: {low[h]}")
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        if h in low and re.search(r"\d+\.\d+", low[h]):
            ctx.finding(f"versi terbuka di {h}", "low", low[h])
    if "access-control-allow-origin" in low and low["access-control-allow-origin"] == "*":
        ctx.finding("CORS wildcard", "medium", "ACAO: *")
    return "audit selesai"


@mod(name="vuln.nikto", category="vuln", desc="Nikto web scanner", needs=["nikto"],
     params={"target": {"required": True, "desc": "host"}})
def nikto(ctx):
    rc, out, err = ctx.exec(["nikto", "-h", ctx.p("target"), "-nointeractive"], 1800)
    ctx.out(out or err)
    for line in out.splitlines():
        if line.strip().startswith("+"):
            ctx.finding("nikto: " + line.strip()[:80], "medium", line.strip())
    ctx.artifact("nikto.txt", out)
    return "nikto selesai"


@mod(name="vuln.whatweb", category="vuln", desc="Fingerprint whatweb", needs=["whatweb"],
     params={"target": {"required": True, "desc": "URL"}})
def whatweb(ctx):
    rc, out, err = ctx.exec(["whatweb", "-a", "3", ctx.p("target")], 300)
    ctx.out(out or err)
    ctx.finding("whatweb fingerprint", "info", out[:1000])
    return "whatweb selesai"


@mod(name="vuln.tls", category="vuln", desc="Audit TLS: versi, cipher, sertifikat",
     params={"target": {"required": True, "desc": "host"}, "port": {"default": 443}})
def tls(ctx):
    info = nu.tls_info(ctx.p("target"), ctx.pi("port"))
    if "error" in info:
        ctx.out(f"  [!] {info['error']}"); return None
    ctx.out(f"  versi: {info['version']}  cipher: {info['cipher']}")
    ctx.out(f"  subjek: {info['subject']}\n  issuer: {info['issuer']}\n  exp: {info['notAfter']}")
    ctx.finding("sertifikat TLS", "info", str(info["subject"]), json.dumps(info, default=str))
    if info["version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        ctx.finding("TLS usang", "medium", info["version"])
    san = info.get("subjectAltName") or ()
    names = [v for _, v in san]
    if names and ctx.p("target") not in " ".join(names):
        ctx.finding("hostname tidak ada di SAN", "low", str(names))
    for proto in ("tls1", "tls1_1"):
        rc, out, _ = ctx.exec(f"echo | openssl s_client -connect {ctx.p('target')}:{ctx.pi('port')} "
                              f"-{proto} 2>/dev/null | grep -m1 'Protocol'", 25)
        if out.strip():
            ctx.out(f"  {proto}: {out.strip()}")
            if proto != "tls1_2":
                ctx.finding(f"{proto} masih aktif", "low", out.strip())
    return "tls selesai"


@mod(name="vuln.summary", category="vuln", desc="Rekap finding per severity", offline=True)
def summary(ctx):
    counts = ctx.db.severity_counts()
    total = sum(counts.values())
    ctx.out(f"  total finding: {total}")
    for k, v in counts.items():
        ctx.out(f"  {k:9} {v}")
    high = ctx.db.q("SELECT title,target FROM findings WHERE severity IN ('high','critical') LIMIT 40")
    for h in high:
        ctx.out(f"  ! {h['title']} @ {h['target']}")
    return f"{total} finding"
