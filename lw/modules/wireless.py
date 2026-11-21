# -*- coding: utf-8 -*-
"""Wireless auditing (Termux API / aircrack-ng)."""
import json

from ..core import netutil as nu
from ._base import MODULES, mod


@mod(name="wifi.scan", category="wireless", desc="Scan SSID sekitar (termux-api)",
     needs=["termux-wifi-scaninfo"])
def scan(ctx):
    rc, out, err = ctx.exec(["termux-wifi-scaninfo"], 40)
    try:
        nets = json.loads(out)
    except Exception:
        ctx.out(out or err); return None
    for n in nets:
        caps = n.get("capabilities") or ""
        sec = "OPEN" if not caps else caps[:40]
        sev = "medium" if not caps or "[WPS]" in caps else "info"
        ctx.out(f"  {n.get('ssid','?'):<28} {n.get('bssid')} ch={n.get('frequency')} "
                f"{n.get('rssi')}dBm {sec}")
        if sev == "medium":
            ctx.finding(f"wifi {sec}: {n.get('ssid')}", sev, f"bssid {n.get('bssid')}")
    ctx.artifact("wifi_scan.json", json.dumps(nets, indent=2))
    return f"{len(nets)} jaringan"


@mod(name="wifi.conn", category="wireless", desc="Info koneksi wifi aktif", offline=True,
     needs=["termux-wifi-connectioninfo"])
def conn(ctx):
    rc, out, err = ctx.exec(["termux-wifi-connectioninfo"], 20)
    ctx.out(out or err)
    try:
        d = json.loads(out)
        ctx.out(f"  ip: {d.get('ip')}  ssid: {d.get('ssid')}  freq: {d.get('frequency')}")
    except Exception:
        pass
    ctx.out(f"  ip lokal: {nu.my_ip()} gateway: {nu.gateway()}")
    return "info koneksi"


@mod(name="wifi.audit", category="wireless", desc="Analisa keamanan jaringan aktif", offline=True)
def audit(ctx):
    if not nu.have("termux-wifi-connectioninfo"):
        ctx.out("  termux-api tidak ada"); return None
    rc, out, _ = ctx.exec(["termux-wifi-connectioninfo"], 20)
    try:
        d = json.loads(out)
    except Exception:
        ctx.out(out); return None
    band = "5GHz" if d.get("frequency", 0) > 4000 else "2.4GHz"
    ctx.out(f"  SSID {d.get('ssid')} band {band} link {d.get('link_speed_mbps')}Mbps "
            f"rssi {d.get('rssi')}")
    if band == "2.4GHz":
        ctx.finding("jaringan 2.4GHz", "low", "rawan interferensi & deauth")
    ctx.out("  [!] handshake capture butuh monitor mode (root/NIC eksternal)")
    return "audit selesai"


@mod(name="wifi.airdump", category="wireless", desc="airodump-ng (butuh root/monitor)",
     needs=["airodump-ng"], root=True, params={"iface": {"default": "wlan0"}})
def airdump(ctx):
    import os
    ctx.out(f"  airodump-ng {ctx.p('iface')} — Ctrl+C stop")
    try:
        os.system(f"airodump-ng {ctx.p('iface')}")
    except KeyboardInterrupt:
        pass
    return "airodump selesai"


@mod(name="wifi.handshake", category="wireless", desc="Capture handshake WPA", needs=["airodump-ng"],
     root=True, params={"iface": {"default": "wlan0mon"}, "bssid": {"required": True, "desc": "BSSID"},
                        "channel": {"default": 6}, "duration": {"default": 60}})
def handshake(ctx):
    import os, time
    base = f"/tmp/lw_hs_{int(time.time())}"
    os.system(f"timeout {ctx.pi('duration')} airodump-ng -c {ctx.pi('channel')} "
              f"--bssid {ctx.p('bssid')} -w {base} {ctx.p('iface')}")
    ctx.out(f"  output: {base}-01.cap")
    ctx.finding("capture handshake", "info", base)
    return base


@mod(name="wifi.wps", category="wireless", desc="Scan WPS (wash)", needs=["wash"], root=True,
     params={"iface": {"default": "wlan0mon"}})
def wps(ctx):
    rc, out, err = ctx.exec(["wash", "-i", ctx.p("iface")], 60)
    ctx.out(out or err)
    for line in out.splitlines():
        if "WPS" in line and "BSSID" not in line:
            ctx.finding("WPS aktif", "medium", line)
    return "wps selesai"


@mod(name="wifi.deauth", category="wireless", desc="Deauth broadcast (aireplay-ng)", needs=["aireplay-ng"],
     root=True, params={"iface": {"default": "wlan0mon"}, "bssid": {"required": True, "desc": "BSSID AP"},
                        "count": {"default": 10}})
def deauth(ctx):
    rc, out, err = ctx.exec(["aireplay-ng", "--deauth", str(ctx.pi("count")), "-a",
                             ctx.p("bssid"), ctx.p("iface")], 120)
    ctx.out(out or err)
    ctx.finding("deauth dikirim", "info", f"{ctx.p('count')} paket ke {ctx.p('bssid')}")
    return "deauth selesai"
