# -*- coding: utf-8 -*-
"""Binary analysis & reverse engineering."""
import re

from ..core import netutil as nu
from ._base import MODULES, mod


@mod(name="bin.file", category="binary", desc="Identifikasi tipe file", needs=["file"],
     params={"target": {"required": True, "desc": "path file"}})
def fileinfo(ctx):
    rc, out, err = ctx.exec(["file", ctx.p("target")], 20)
    ctx.out(out or err)
    ctx.finding("tipe file", "info", out.strip())
    return out


@mod(name="bin.strings", category="binary", desc="Ekstrak string menarik", needs=["strings"],
     params={"target": {"required": True, "desc": "path file"},
             "pattern": {"default": "pass|key|token|http|flag|admin|secret"}})
def strings(ctx):
    rc, out, err = ctx.exec(["strings", "-n", "5", ctx.p("target")], 120)
    hits = [l for l in out.splitlines() if re.search(ctx.p("pattern"), l, re.I)]
    for h in hits[:200]:
        ctx.out(f"  {h}")
    if hits:
        ctx.finding("string sensitif", "medium", f"{len(hits)} kandidat", "\n".join(hits[:100]))
    return f"{len(hits)} hit"


@mod(name="bin.elf", category="binary", desc="Header ELF + section", needs=["readelf"],
     params={"target": {"required": True, "desc": "path ELF"}})
def elf(ctx):
    for args in (["-hW"], ["-lW"], ["-SW"]):
        rc, out, err = ctx.exec(["readelf"] + args + [ctx.p("target")], 30)
        ctx.out(out[:2500] or err)
    return "elf selesai"


@mod(name="bin.checksec", category="binary", desc="Cek hardening binary (NX/PIE/RELRO)", needs=["readelf"],
     params={"target": {"required": True, "desc": "path ELF"}})
def checksec(ctx):
    rc, hdr, _ = ctx.exec(["readelf", "-hW", ctx.p("target")], 20)
    rc2, prog, _ = ctx.exec(["readelf", "-lW", ctx.p("target")], 20)
    rc3, dyn, _ = ctx.exec(["readelf", "-dW", ctx.p("target")], 20)
    pie = "DYN" in hdr.split("Type:")[1][:40] if "Type:" in hdr else False
    nx = "GNU_STACK" in prog and "RWE" not in re.search(r"GNU_STACK.*", prog).group(0)
    relro = "GNU_RELRO" in prog
    now = "BIND_NOW" in dyn
    ctx.out(f"  PIE: {'ya' if pie else 'TIDAK'}  NX: {'ya' if nx else 'TIDAK'}  "
            f"RELRO: {'full' if relro and now else 'partial' if relro else 'TIDAK'}")
    for name, bad, sev in (("tanpa PIE", not pie, "medium"), ("stack executable", not nx, "high"),
                           ("tanpa RELRO", not relro, "low")):
        if bad:
            ctx.finding(name, sev, ctx.p("target"))
    return "checksec selesai"


@mod(name="bin.disasm", category="binary", desc="Disassembly fungsi", needs=["objdump"],
     params={"target": {"required": True, "desc": "path ELF"},
             "symbol": {"default": "main", "desc": "nama fungsi"}})
def disasm(ctx):
    rc, out, err = ctx.exec(["objdump", "-d", "-M", "intel",
                             f"--disassemble={ctx.p('symbol')}", ctx.p("target")], 60)
    ctx.out(out[:5000] or err)
    ctx.artifact("disasm.asm", out)
    return "disasm selesai"


@mod(name="bin.rop", category="binary", desc="Cari gadget ROP", needs=["ROPgadget"],
     params={"target": {"required": True, "desc": "path ELF"},
             "pattern": {"default": "pop rdi"}})
def rop(ctx):
    rc, out, err = ctx.exec(["ROPgadget", "--binary", ctx.p("target"),
                             "--only", "pop|ret"], 180)
    lines = [l for l in out.splitlines() if ctx.p("pattern") in l]
    for l in lines[:60]:
        ctx.out(f"  {l}")
    ctx.artifact("gadgets.txt", "\n".join(lines))
    return f"{len(lines)} gadget"


@mod(name="bin.binwalk", category="binary", desc="Binwalk signature scan", needs=["binwalk"],
     params={"target": {"required": True, "desc": "path file"}})
def binwalk(ctx):
    rc, out, err = ctx.exec(["binwalk", ctx.p("target")], 180)
    ctx.out(out or err)
    return "binwalk selesai"


@mod(name="bin.frida", category="binary", desc="Proses frida-server aktif", offline=True)
def frida(ctx):
    rc, out, err = ctx.exec(["frida-ps", "-U"], 40)
    if rc != 0:
        ctx.out("  frida-ps tidak ada / server belum jalan")
        return None
    ctx.out(out[:3000])
    ctx.finding("frida terhubung", "info", f"{len(out.splitlines())} proses")
    return "frida selesai"


@mod(name="bin.hash", category="binary", desc="Hash file (sha256/md5)", offline=True,
     params={"target": {"required": True, "desc": "path file"}})
def hashfile(ctx):
    import hashlib
    h256 = hashlib.sha256()
    hmd5 = hashlib.md5()
    with open(ctx.p("target"), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h256.update(chunk); hmd5.update(chunk)
    ctx.out(f"  sha256 {h256.hexdigest()}\n  md5    {hmd5.hexdigest()}")
    ctx.finding("hash file", "info", h256.hexdigest())
    return h256.hexdigest()
