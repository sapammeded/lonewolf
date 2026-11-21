# -*- coding: utf-8 -*-
"""Discovery, port scan, fingerprint, mapping."""
import re
import socket

from ..core import netutil as nu
from ._base import MODULES, mod

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
             7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017]

SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
            110: "pop3", 143: "imap", 443: "https", 445: "smb", 1433: "mssql",
            3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"}


@mod(name="net.discover", category="network", desc="Host discovery (nmap/ARP/ping sweep)",
     params={"target": {"default": None, "desc": "CIDR, kosong = subnet lokal"}})
def discover(ctx):
    t = ctx.p("target") or nu.local_cidr()
    ctx.out(f"  target: {t}")
    if nu.have("nmap"):
        rc, out, err = ctx.exec(["nmap", "-sn", "-T4", t], 300)
        ctx.out(out or err)
        hosts = re.findall(r"Nmap scan report for (?:(\S+) \()?([\d.]+)\)?", out)
        for name, ip in hosts:
            ctx.host(ip, ip, "host", name)
            ctx.finding("host hidup", "info", f"{ip} {name}".strip())
        ctx.artifact("discover.txt", out)
        return f"{len(hosts)} host"
    ctx.out("  nmap tidak ada, fallback ARP + ping")
    arp = nu.arp_table()
    ips = set(arp) | set(nu.expand(t))
    alive = nu.parallel(sorted(ips), lambda ip: ip if nu.ping(ip) else None, ctx.pi("threads"))
    for ip in alive:
        ctx.out(f"  UP {ip} {arp.get(ip,'')}")
        ctx.host(ip, ip, "host", arp.get(ip, ""))
        ctx.finding("host hidup", "info", f"{ip} {arp.get(ip,'')}")
    return f"{len(alive)} host"


@mod(name="net.portscan", category="network", desc="Port scan (nmap/masscan/socket)",
     params={"target": {"required": True, "desc": "IP / host"},
             "ports": {"default": None, "desc": "spesifikasi port, kosong = top 36"},
             "threads": {"default": 64}})
def portscan(ctx):
    t = ctx.p("target")
    ip = (nu.resolve(t) or [t])[0]
    tid = ctx.host(t, ip, "scan")
    spec = ctx.p("ports")
    if nu.have("nmap"):
        args = ctx.cfg.get("nmap_args", "-sT -Pn --open -T4").split()
        cmd = ["nmap"] + args + (["-p", spec] if spec else ["--top-ports", "100"]) + [t]
        ctx.out(f"  {' '.join(cmd)}")
        rc, out, err = ctx.exec(cmd, 900)
        ctx.out(out or err)
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)$", out, re.M):
            ctx.port(tid, int(m.group(1)), m.group(2), "open", m.group(3), m.group(4).strip())
            ctx.finding(f"port terbuka {m.group(1)}/{m.group(2)}", "low", m.group(3))
        ctx.artifact("portscan.txt", out)
        return "nmap selesai"
    ports = [int(x) for x in spec.split(",")] if spec else TOP_PORTS
    ctx.out(f"  fallback socket ke {len(ports)} port")
    hits = nu.parallel(ports, lambda p: p if nu.tcp_open(ip, p, 1.5) else None, ctx.pi("threads"))
    for p in hits:
        svc = SERVICES.get(p, "")
        ctx.out(f"  OPEN {p}/{svc}")
        ctx.port(tid, p, "tcp", "open", svc)
        ctx.finding(f"port terbuka {p}", "low", svc or "unknown")
    return f"{len(hits)} port terbuka"


@mod(name="net.fingerprint", category="network", desc="Banner grab + service fingerprint",
     params={"target": {"required": True, "desc": "IP / host"},
             "ports": {"default": None, "desc": "port, kosong = top 36"}})
def fingerprint(ctx):
    ip = (nu.resolve(ctx.p("target")) or [ctx.p("target")])[0]
    spec = ctx.p("ports")
    ports = [int(x) for x in spec.split(",")] if spec else TOP_PORTS
    openp = nu.parallel(ports, lambda p: p if nu.tcp_open(ip, p, 1.2) else None, 48)
    for p in openp:
        banner = nu.grab_banner(ip, p, 3)
        if banner:
            first = banner.splitlines()[0][:120]
            ctx.out(f"  {p}: {first}")
            ctx.finding(f"banner port {p}", "info", first, banner[:500])
            tid = ctx.host(ctx.p("target"), ip, "scan")
            ctx.port(tid, p, "tcp", "open", SERVICES.get(p, ""), first, banner)
    if nu.have("nmap") and openp:
        rc, out, _ = ctx.exec(["nmap", "-sV", "-Pn", "-p", ",".join(map(str, openp)), ip], 600)
        ctx.out(out)
        ctx.artifact("fingerprint.txt", out)
    return f"{len(openp)} port diprofilkan"


@mod(name="net.udp", category="network", desc="UDP scan port umum", needs=["nmap"],
     params={"target": {"required": True, "desc": "IP"}})
def udp(ctx):
    rc, out, err = ctx.exec(["nmap", "-sU", "-Pn", "--top-ports", "20", ctx.p("target")], 900)
    ctx.out(out or err)
    for m in re.finditer(r"^(\d+)/udp\s+open\s*(\S*)", out, re.M):
        ctx.finding(f"UDP terbuka {m.group(1)}", "low", m.group(2))
    ctx.artifact("udp.txt", out)
    return "udp selesai"


@mod(name="net.os", category="network", desc="OS fingerprint", needs=["nmap"], root=True,
     params={"target": {"required": True, "desc": "IP"}})
def osfp(ctx):
    rc, out, err = ctx.exec(["nmap", "-O", "--osscan-guess", "-Pn", ctx.p("target")], 600)
    ctx.out(out or err)
    for line in out.splitlines():
        if re.search(r"(?i)(OS details|Running:|Aggressive OS)", line):
            ctx.finding("OS terdeteksi", "info", line.strip())
    return "os selesai"


@mod(name="net.traceroute", category="network", desc="Traceroute ke target",
     params={"target": {"required": True, "desc": "host"}})
def traceroute(ctx):
    if nu.have("traceroute"):
        rc, out, err = ctx.exec(["traceroute", "-n", "-m", "20", ctx.p("target")], 120)
    elif nu.have("nmap"):
        rc, out, err = ctx.exec(["nmap", "--traceroute", "-Pn", "-p", "80", ctx.p("target")], 180)
    else:
        ctx.out("  traceroute/nmap tidak ada"); return None
    ctx.out(out or err)
    ctx.finding("jalur jaringan", "info", "traceroute", out[:2000])
    return "traceroute selesai"


@mod(name="net.localinfo", category="network", desc="Info antarmuka & rute lokal", offline=True)
def localinfo(ctx):
    ctx.out(f"  ip: {nu.my_ip()}  gateway: {nu.gateway()}  cidr: {nu.local_cidr()}")
    for f in ("/proc/net/route", "/proc/net/arp"):
        try:
            ctx.out(f"\n  [{f}]")
            ctx.out(open(f).read()[:1500])
        except Exception as e:
            ctx.out(f"  {e}")
    if nu.have("ip"):
        ctx.out(ctx.exec(["ip", "addr"], 15)[1])
    return "info lokal selesai"


@mod(name="net.mapping", category="network", desc="Peta host+port jadi artefak JSON",
     params={"target": {"default": None, "desc": "CIDR, kosong = lokal"}})
def mapping(ctx):
    import json
    t = ctx.p("target") or nu.local_cidr()
    ips = nu.expand(t, 512)
    alive = nu.parallel(ips, lambda ip: ip if nu.ping(ip) else None, 64)
    ctx.out(f"  {len(alive)} host hidup dari {len(ips)}")
    data = {}
    for ip in alive:
        ports = nu.parallel(TOP_PORTS, lambda p: p if nu.tcp_open(ip, p, 1) else None, 48)
        data[ip] = ports
        ctx.out(f"  {ip}: {ports or '-'}")
        tid = ctx.host(ip, ip, "map")
        for p in ports:
            ctx.port(tid, p, "tcp", "open", SERVICES.get(p, ""))
    ctx.artifact("map.json", json.dumps(data, indent=2))
    return f"{len(alive)} host dipetakan"
