# -*- coding: utf-8 -*-
"""Bluetooth: scan, info, popup spam BLE."""
import time

from ..core import netutil as nu
from ._base import MODULES, mod

NAMES = ["AirPods Pro", "AirPods Max", "Galaxy Buds2", "JBL Flip 6", "Pixel Buds Pro",
         "Bose QC45", "Sony WH-1000XM5", "Swift Pair Mouse", "Mi Band 8", "Beats Studio3",
         "Windows Keyboard", "Logitech MX", "Tesla Model 3", "Soundcore Boost"]


def _sh(cmd):
    import subprocess
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15,
                              errors="replace").stdout
    except Exception as e:
        return str(e)


@mod(name="bt.scan", category="bluetooth", desc="Scan perangkat Bluetooth sekitar",
     needs=["hcitool"])
def scan(ctx):
    ctx.out("  scan 12 detik...")
    if nu.have("hcitool"):
        out = _sh("hcitool scan --flush")
    else:
        out = _sh("bluetoothctl --timeout 10 scan on")
    ctx.out(out)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ctx.finding("perangkat BT", "info", f"{parts[0]} {parts[1]}")
    return "scan selesai"


@mod(name="bt.info", category="bluetooth", desc="Info adapter & service lokal", offline=True)
def info(ctx):
    ctx.out(_sh("hciconfig -a 2>&1 | head -30"))
    ctx.out(_sh("bluetoothctl show 2>&1 | head -20"))
    return "info bt"


@mod(name="bt.spam", category="bluetooth", desc="Popup spam BLE (rotasi nama device)",
     needs=["hcitool"], root=True,
     params={"names": {"default": None, "desc": "nama dipisah koma"},
             "delay": {"default": 1.5}, "duration": {"default": 0}})
def spam(ctx):
    names = [n.strip() for n in ctx.p("names").split(",")] if ctx.p("names") else NAMES
    delay = float(ctx.p("delay"))
    end = time.time() + ctx.pi("duration")
    ctx.out(f"  {len(names)} nama, jeda {delay}s — Ctrl+C stop")

    def adv(name):
        n = name.encode()[:20]
        data = bytes([0x02, 0x01, 0x06, len(n) + 1, 0x09]) + n
        hexd = " ".join(f"{b:02x}" for b in data)
        _sh(f"hcitool -i hci0 cmd 0x08 0x0008 {len(data):02x} {hexd}")
        _sh("hcitool -i hci0 cmd 0x08 0x000a 01")

    i = 0
    try:
        while not ctx.stopped and (ctx.pi("duration") == 0 or time.time() < end):
            nm = names[i % len(names)]
            adv(nm)
            ctx.out(f"  -> {nm}")
            i += 1
            time.sleep(delay)
    finally:
        _sh("hcitool -i hci0 cmd 0x08 0x000a 00")
    ctx.finding("bt spam", "info", f"{i} paket advertising")
    return f"{i} paket"
