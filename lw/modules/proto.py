# -*- coding: utf-8 -*-
"""Protocol analysis & misconfiguration."""
import socket

from ..core import netutil as nu
from ._base import MODULES, mod


def _talk(host, port, payload, timeout=6, size=2048):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    if payload:
        s.sendall(payload)
    data = s.recv(size)
    s.close()
    return data.decode(errors="replace")


@mod(name="proto.redis", category="proto", desc="Cek Redis tanpa auth",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 6379}})
def redis(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"PING\r\nINFO server\r\n")
        ctx.out(out[:1200])
        if "+PONG" in out:
            ctx.finding("Redis tanpa auth", "high", "PING berhasil", out[:400])
            ctx.out("  -> coba: redis-cli -h target KEYS *")
    except Exception as e:
        ctx.out(f"  {e}")
    return "redis selesai"


@mod(name="proto.mqtt", category="proto", desc="Cek broker MQTT anonim",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 1883}})
def mqtt(ctx):
    try:
        s = socket.socket(); s.settimeout(6)
        s.connect((ctx.p("target"), ctx.pi("port")))
        cid = b"lw-probe"
        vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
        payload = len(cid).to_bytes(2, "big") + cid
        body = vh + payload
        s.sendall(bytes([0x10, len(body)]) + body)
        resp = s.recv(64)
        s.close()
        ctx.out(f"  connack: {resp.hex()}")
        if len(resp) >= 4 and resp[3] == 0:
            ctx.finding("MQTT anonim diterima", "high", "CONNACK rc=0")
        elif len(resp) >= 4:
            ctx.finding("MQTT butuh auth", "low", f"rc={resp[3]}")
    except Exception as e:
        ctx.out(f"  {e}")
    return "mqtt selesai"


@mod(name="proto.ftp", category="proto", desc="Cek FTP anonim & banner",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 21}})
def ftp(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"")
        ctx.out(out.strip())
        user = _talk(ctx.p("target"), ctx.pi("port"), b"USER anonymous\r\n")
        ctx.out(user.strip())
        if "331" in user:
            pw = _talk(ctx.p("target"), ctx.pi("port"), b"USER anonymous\r\nPASS lw@test\r\n")
            if "230" in pw:
                ctx.finding("FTP anonim", "high", "login anonim diterima")
                ctx.cred("anonymous", "lw@test", "anon-ftp")
    except Exception as e:
        ctx.out(f"  {e}")
    return "ftp selesai"


@mod(name="proto.smtp", category="proto", desc="Banner + VRFY SMTP",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 25}})
def smtp(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"EHLO lw\r\n")
        ctx.out(out[:800])
        if "250" in out:
            ctx.finding("SMTP terbuka", "low", "EHLO diterima")
            v = _talk(ctx.p("target"), ctx.pi("port"), b"VRFY root\r\n")
            ctx.out(v.strip())
    except Exception as e:
        ctx.out(f"  {e}")
    return "smtp selesai"


@mod(name="proto.axfr", category="proto", desc="Uji DNS zone transfer",
     params={"target": {"required": True, "desc": "domain"},
             "ns": {"required": True, "desc": "nameserver"}})
def axfr(ctx):
    rc, out, err = ctx.exec(["dig", "AXFR", ctx.p("target"), "@" + ctx.p("ns")], 45)
    ctx.out(out or err)
    if "XFR size" in out:
        ctx.finding("zone transfer terbuka", "medium", out.splitlines()[0][:200])
    return "axfr selesai"


@mod(name="proto.ldap", category="proto", desc="RootDSE LDAP anonim",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 389}})
def ldap(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
        ctx.out(out[:600])
        if "rootDomainNamingContext" in out or "namingContexts" in out:
            ctx.finding("LDAP rootDSE terbuka", "low", "anon bind")
    except Exception as e:
        ctx.out(f"  {e}")
    return "ldap selesai"


@mod(name="proto.mongo", category="proto", desc="Cek MongoDB tanpa auth",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 27017}})
def mongo(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                               b"\xdd\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                                               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        ctx.out(f"  {len(out)} byte balasan")
        if len(out) > 16:
            ctx.finding("MongoDB merespons", "medium", "kemungkinan tanpa auth")
    except Exception as e:
        ctx.out(f"  {e}")
    return "mongo selesai"


@mod(name="proto.telnet", category="proto", desc="Banner telnet",
     params={"target": {"required": True, "desc": "IP"}, "port": {"default": 23}})
def telnet(ctx):
    try:
        out = _talk(ctx.p("target"), ctx.pi("port"), b"\r\n")
        ctx.out(out[:400])
        ctx.finding("telnet terbuka (plaintext)", "medium", out[:200])
    except Exception as e:
        ctx.out(f"  {e}")
    return "telnet selesai"


@mod(name="proto.snmp", category="proto", desc="SNMP community string umum",
     needs=["snmpwalk"], params={"target": {"required": True, "desc": "IP"}})
def snmp(ctx):
    for c in ("public", "private", "community"):
        rc, out, err = ctx.exec(["snmpwalk", "-v1", "-c", c, "-t", "3", ctx.p("target"),
                                 "1.3.6.1.2.1.1"], 25)
        if "SNMPv2-MIB" in out or "STRING:" in out:
            ctx.out(f"  community '{c}' valid")
            ctx.out(out[:800])
            ctx.cred("snmp", c, "community")
    return "snmp selesai"
