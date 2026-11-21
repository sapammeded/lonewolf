# -*- coding: utf-8 -*-
"""Menu 12 kategori. Fitur v2.1 dipertahankan, kini memanggil modul nyata."""
import os
import shutil
import time

from ..core import deps, module_loader, reporting, runner
from ..core.config import Config
from ..core.logger import col, B, C, D, G, M, R, W, Y
from ..core.workspace import Workspace
from .banner import banner_text, logo_text

MENU = [
    ("1", "Reconnaissance & Footprinting", "recon"),
    ("2", "Network Scanning (Nmap/Masscan)", "network"),
    ("3", "Vulnerability Assessment", "vuln"),
    ("4", "Exploitation Frameworks", "exploit"),
    ("5", "Password Cracking (John/Hashcat)", "auth"),
    ("6", "Social Engineering Suite", "se"),
    ("7", "Web Application Hacking", "web"),
    ("8", "Privilege Escalation", "privesc"),
    ("9", "Wireless Network Auditing", "wireless"),
    ("10", "Bluetooth Popup Spam", "bluetooth"),
    ("11", "MITM / Traffic Intercept", "mitm"),
    ("12", "Wi-Fi Broadcast Message", "broadcast"),
]


def clear():
    os.system("clear" if shutil.which("clear") else "cls")


def ask(prompt, default=""):
    v = input(f"{C}{prompt}{N}" + (f" {D}[{default}]{N}" if default else "") + ": ").strip()
    return v or default


def draw(ws):
    clear()
    print(col(banner_text(), R))
    print(col(logo_text(), Y))
    print(col("\n[---- LONE WOLF 2026 — OFFENSIVE FRAMEWORK v3.0 ----]", Y))
    print(col("[---- HACKER UTILITIES MENU -----------------------]", Y))
    print(col("-" * 56, D))
    for key, title, cat in MENU:
        n = len(module_loader.by_category(cat))
        print(f"{col('[' + key + ']', M if len(key) == 2 else G)} {col(title, C)} {D}({n} modul){N}")
    print(f"{col('[c]', G)} {col('Console', C)}   {col('[r]', G)} {col('Report', C)}"
          f"   {col('[d]', G)} {col('Doctor', C)}   {col('[x]', R)} {col('Exit', C)}")
    print(col("-" * 56, D))
    st = ws.db.stats()
    print(f"{W}WORKSPACE:{N} {col(ws.name, G)}  "
          f"{D}target={st['targets']} port={st['ports']} finding={st['findings']} "
          f"cred={st['creds']}{N}")
    print(col("pilih opsi untuk memulai...", D))


def pick_module(cat):
    mods = module_loader.by_category(cat)
    if not mods:
        print(col("  kosong", Y))
        return None
    print()
    for i, m in enumerate(mods, 1):
        need = f" {D}[{','.join(m['needs'])}]{N}" if m.get("needs") else ""
        print(f"  {col(str(i), G)}. {m['name']} — {m['desc']}{need}")
    sel = ask("\n  pilih nomor (kosong = kembali)")
    try:
        return mods[int(sel) - 1]
    except (ValueError, IndexError):
        return None


def collect(meta, args):
    for key, spec in (meta.get("params") or {}).items():
        if spec.get("required"):
            val = ask(f"  {key} ({spec.get('desc','')})", args.get(key) or "")
            if not val:
                return None
            args[key] = val
        elif spec.get("ask"):
            val = ask(f"  {key} ({spec.get('desc','')})", str(spec.get("default", "")))
            if val:
                args[key] = val
    return args


def run_menu(ws: Workspace, cfg: Config):
    while True:
        module_loader.registry()
        draw(ws)
        try:
            ch = input(f"\n{W}${N} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break
        if ch in ("x", "q"):
            break
        if ch == "c":
            from ..core.console import Console
            Console(ws).loop()
            continue
        if ch == "d":
            clear()
            for tool, ok, pkg in deps.doctor():
                print(f"  {col('OK  ' if ok else 'MISS', G if ok else R)} {tool:<22} {D}{pkg}{N}")
            input(f"\n{D}[enter]{N} ")
            continue
        if ch == "r":
            fmt = ask("format (md/json/html)", "md")
            print(col(f"\n[+] {reporting.generate(ws.db, ws.name, fmt)}", G))
            input(f"{D}[enter]{N} ")
            continue

        cat = dict((k, c) for k, _, c in MENU).get(ch)
        if not cat:
            continue
        meta = pick_module(cat)
        if not meta:
            continue
        args = collect(meta, {})
        if args is None:
            continue
        clear()
        runner.execute(meta["name"], args, ws.db, cfg, bg=False)
        input(f"\n{D}[enter]{N} ")
