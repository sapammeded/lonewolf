# -*- coding: utf-8 -*-
"""Reporting engine: markdown, json, html mandiri."""
import html
import json
import time
from pathlib import Path

from .config import OUT_ROOT, ensure_dirs


def _report_path(fmt, workspace):
    ensure_dirs()
    d = OUT_ROOT / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{workspace}_{time.strftime('%Y%m%d_%H%M%S')}.{fmt}"


def to_json(db, workspace):
    p = _report_path("json", workspace)
    p.write_text(json.dumps({
        "workspace": workspace,
        "generated": time.time(),
        "stats": db.stats(),
        "severity": db.severity_counts(),
        "targets": db.q("SELECT * FROM targets"),
        "ports": db.q("SELECT * FROM ports"),
        "findings": db.findings(1000),
        "creds": db.creds(1000),
        "artifacts": db.q("SELECT * FROM artifacts"),
        "jobs": db.q("SELECT * FROM jobs"),
        "sessions": db.q("SELECT * FROM sessions"),
    }, indent=2, default=str))
    return p


def to_markdown(db, workspace):
    p = _report_path("md", workspace)
    sev = db.severity_counts()
    stats = db.stats()
    lines = [f"# LONE WOLF Report — {workspace}", "",
             f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
             "## Ringkasan", "",
             f"- Target: {stats['targets']}", f"- Port: {stats['ports']}",
             f"- Finding: {stats['findings']}", f"- Kredensial: {stats['creds']}", "",
             "| Severity | Jumlah |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sev.items()]
    lines += ["", "## Finding", ""]
    for f in db.findings(1000):
        lines += [f"### [{f['severity'].upper()}] {f['title']}", "",
                  f"- target: `{f['target']}`", f"- modul: `{f['module']}`",
                  f"- detail: {f['detail']}", ""]
        if f["evidence"]:
            lines += ["```", f["evidence"][:3000], "```", ""]
    lines += ["## Kredensial", ""]
    for c in db.creds(1000):
        lines.append(f"- `{c['target']}` — {c['username']}:{c['secret']} ({c['kind']})")
    p.write_text("\n".join(lines))
    return p


HTML_CSS = """
body{background:#0b0f14;color:#e6edf3;font-family:ui-monospace,monospace;margin:0;padding:32px}
h1,h2{color:#58a6ff}h1{border-bottom:1px solid #30363d;padding-bottom:10px}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #30363d;padding:7px 10px;text-align:left;font-size:13px}
th{background:#161b22}.sev{font-weight:700;padding:2px 8px;border-radius:4px}
.critical{background:#6e1b3a;color:#ffb3c8}.high{background:#5c1f10;color:#ffb199}
.medium{background:#4d3d0a;color:#ffd76e}.low{background:#123b2a;color:#8ce0b4}
.info{background:#1b2a3b;color:#9cc8f5}pre{background:#161b22;padding:12px;overflow:auto;border-radius:8px}
.card{background:#11161d;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}
"""


def to_html(db, workspace):
    p = _report_path("html", workspace)
    sev = db.severity_counts()
    stats = db.stats()
    esc = html.escape
    rows = "".join(f"<tr><td>{esc(f['target'])}</td><td><span class='sev {f['severity']}'>"
                   f"{f['severity']}</span></td><td>{esc(f['title'])}</td>"
                   f"<td>{esc(f['module'])}</td></tr>" for f in db.findings(1000))
    creds = "".join(f"<tr><td>{esc(c['target'])}</td><td>{esc(c['username'])}</td>"
                    f"<td>{esc(c['secret'])}</td><td>{esc(c['kind'])}</td></tr>" for c in db.creds(1000))
    body = f"""<!doctype html><meta charset=utf-8><title>LW Report {esc(workspace)}</title>
<style>{HTML_CSS}</style><h1>LONE WOLF Report — {esc(workspace)}</h1>
<p>{time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class=card>Target {stats['targets']} · Port {stats['ports']} · Finding {stats['findings']}
 · Kredensial {stats['creds']} · Job {stats['jobs']}</div>
<h2>Severity</h2><table><tr><th>Severity</th><th>Jumlah</th></tr>
{''.join(f'<tr><td><span class="sev {k}">{k}</span></td><td>{v}</td></tr>' for k, v in sev.items())}</table>
<h2>Finding</h2><table><tr><th>Target</th><th>Sev</th><th>Judul</th><th>Modul</th></tr>{rows}</table>
<h2>Kredensial</h2><table><tr><th>Target</th><th>User</th><th>Secret</th><th>Jenis</th></tr>{creds}</table>"""
    p.write_text(body)
    return p


def generate(db, workspace, fmt="md"):
    fmt = fmt.lower()
    if fmt in ("md", "markdown"):
        return to_markdown(db, workspace)
    if fmt == "json":
        return to_json(db, workspace)
    if fmt in ("html", "htm"):
        return to_html(db, workspace)
    raise ValueError(f"format tidak dikenal: {fmt}")
