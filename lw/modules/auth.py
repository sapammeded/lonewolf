# -*- coding: utf-8 -*-
"""Password & authentication."""
import random
import re

from ..core import netutil as nu
from ._base import MODULES, mod

PATTERNS = [(r"^\$2[aby]\$", "bcrypt", "bcrypt"), (r"^\$6\$", "sha512crypt", "sha512crypt"),
            (r"^\$5\$", "sha256crypt", "sha256crypt"), (r"^\$1\$", "md5crypt", "md5crypt"),
            (r"^\$argon2", "argon2", "argon2"), (r"^[a-f0-9]{32}$", "md5 / NTLM", "raw-md5 / nt"),
            (r"^[a-f0-9]{40}$", "sha1", "raw-sha1"), (r"^[a-f0-9]{64}$", "sha256", "raw-sha256"),
            (r"^[a-f0-9]{128}$", "sha512", "raw-sha512"),
            (r"^\{(SSHA|SHA)\}", "LDAP SSHA", "ssha"),
            (r"^\$pbkdf2", "pbkdf2", "pbkdf2")]


@mod(name="auth.identify", category="auth", desc="Identifikasi tipe hash", offline=True,
     params={"target": {"required": True, "desc": "string hash"}})
def identify(ctx):
    h = ctx.p("target").strip()
    hits = [(n, f) for p, n, f in PATTERNS if re.match(p, h, re.I)]
    if hits:
        for n, f in hits:
            ctx.out(f"  -> {n}   john={f}")
            ctx.finding(f"hash {n}", "info", f"format john: {f}")
    else:
        ctx.out("  tidak dikenali")
    ctx.out(f"  panjang: {len(h)}")
    return hits


@mod(name="auth.john", category="auth", desc="John the Ripper", needs=["john"],
     params={"target": {"required": True, "desc": "file hash"},
             "wordlist": {"default": None}})
def john(ctx):
    wl = ctx.p("wordlist") or "/sdcard/wordlist.txt"
    rc, out, err = ctx.exec(["john", "--wordlist=" + wl, ctx.p("target")], 7200)
    ctx.out(out or err)
    rc2, show, _ = ctx.exec(["john", "--show", ctx.p("target")], 60)
    ctx.out(show)
    for line in show.splitlines():
        if ":" in line and "password hash" not in line:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1]:
                ctx.cred(parts[0], parts[1], "hash", "john")
    return "john selesai"


@mod(name="auth.hashcat", category="auth", desc="Hashcat", needs=["hashcat"],
     params={"target": {"required": True, "desc": "hash"},
             "mode": {"default": 0}, "wordlist": {"default": None}})
def hashcat(ctx):
    wl = ctx.p("wordlist") or "/sdcard/wordlist.txt"
    rc, out, err = ctx.exec(["hashcat", "-m", str(ctx.pi("mode")), ctx.p("target"), wl, "--force"], 7200)
    ctx.out((out or err)[-4000:])
    return "hashcat selesai"


@mod(name="auth.wordlist", category="auth", desc="Generator wordlist", offline=True,
     params={"charset": {"default": "abcdefghijklmnopqrstuvwxyz0123456789"},
             "length": {"default": 4}, "count": {"default": 5000}})
def wordlist(ctx):
    cs = ctx.p("charset")
    ln = max(1, ctx.pi("length"))
    cnt = max(1, ctx.pi("count"))
    lines = {"".join(random.choice(cs) for _ in range(ln)) for _ in range(cnt)}
    p = ctx.artifact(f"wordlist_{ln}x{cnt}.txt", "\n".join(sorted(lines)))
    ctx.out(f"  {len(lines)} kata -> {p}")
    return f"{len(lines)} baris"


@mod(name="auth.hydra", category="auth", desc="Hydra brute (ssh/ftp/http)",
     needs=["hydra"],
     params={"target": {"required": True, "desc": "IP/host"},
             "service": {"default": "ssh", "desc": "ssh/ftp/rdp/mysql"},
             "user": {"required": True, "desc": "username atau file -L"},
             "wordlist": {"default": None}, "threads": {"default": 8}})
def hydra(ctx):
    wl = ctx.p("wordlist") or "/sdcard/wordlist.txt"
    rc, out, err = ctx.exec(["hydra", "-t", str(ctx.pi("threads")), "-l", ctx.p("user"),
                             "-P", wl, ctx.p("target"), ctx.p("service")], 3600)
    ctx.out(out or err)
    for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", out):
        ctx.cred(m.group(1), m.group(2), "password", f"hydra/{ctx.p('service')}")
    return "hydra selesai"


@mod(name="auth.sshcheck", category="auth", desc="Cek auth method SSH (tanpa login)",
     params={"target": {"required": True, "desc": "IP/host"}, "port": {"default": 22}})
def sshcheck(ctx):
    import socket
    try:
        s = socket.socket()
        s.settimeout(8)
        s.connect((ctx.p("target"), ctx.pi("port")))
        s.sendall(b"SSH-2.0-LW\r\n")
        banner = s.recv(255).decode(errors="replace").strip()
        s.close()
        ctx.out(f"  banner: {banner}")
        ctx.finding("SSH terbuka", "low", banner)
        if "SSH-2.0" in banner and "1.99" not in banner:
            ctx.finding("SSH protokol 2", "info", "hanya v2")
    except Exception as e:
        ctx.out(f"  {e}")
    return "ssh check selesai"


@mod(name="auth.creds", category="auth", desc="Daftar kredensial terkumpul", offline=True)
def creds(ctx):
    rows = ctx.db.creds(200)
    for c in rows:
        ctx.out(f"  {c['target']} {c['username']}:{c['secret']} ({c['kind']} via {c['source']})")
    return f"{len(rows)} kredensial"
