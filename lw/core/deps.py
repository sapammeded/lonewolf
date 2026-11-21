# -*- coding: utf-8 -*-
"""Deteksi dependensi + perintah instalasi untuk Termux dan Linux."""
import os
import platform
import shutil

TOOLS = {
    "nmap": {"pkg": "nmap", "apt": "nmap"},
    "masscan": {"pkg": "masscan", "apt": "masscan"},
    "whois": {"pkg": "whois", "apt": "whois"},
    "dig": {"pkg": "dnsutils", "apt": "dnsutils"},
    "host": {"pkg": "dnsutils", "apt": "dnsutils"},
    "nikto": {"pkg": "nikto", "apt": "nikto"},
    "whatweb": {"pkg": "whatweb", "apt": "whatweb"},
    "sqlmap": {"pkg": "sqlmap", "apt": "sqlmap"},
    "searchsploit": {"pkg": "exploitdb", "apt": "exploitdb"},
    "msfvenom": {"pkg": "metasploit", "apt": "metasploit-framework"},
    "msfconsole": {"pkg": "metasploit", "apt": "metasploit-framework"},
    "john": {"pkg": "john", "apt": "john"},
    "hashcat": {"pkg": "hashcat", "apt": "hashcat"},
    "hydra": {"pkg": "hydra", "apt": "hydra"},
    "nc": {"pkg": "netcat-openbsd", "apt": "netcat-openbsd"},
    "socat": {"pkg": "socat", "apt": "socat"},
    "tcpdump": {"pkg": "tcpdump", "apt": "tcpdump"},
    "openssl": {"pkg": "openssl-tool", "apt": "openssl"},
    "mitmproxy": {"pkg": None, "pip": "mitmproxy"},
    "scapy": {"pkg": None, "pip": "scapy"},
    "aircrack-ng": {"pkg": "aircrack-ng", "apt": "aircrack-ng"},
    "hcitool": {"pkg": "bluez-utils", "apt": "bluez"},
    "termux-wifi-scaninfo": {"pkg": "termux-api", "apt": None},
    "gcc": {"pkg": "clang", "apt": "gcc"},
    "go": {"pkg": "golang", "apt": "golang"},
    "rustc": {"pkg": "rust", "apt": "rustc"},
    "node": {"pkg": "nodejs", "apt": "nodejs"},
    "php": {"pkg": "php", "apt": "php-cli"},
    "binwalk": {"pkg": "binwalk", "apt": "binwalk"},
    "readelf": {"pkg": "binutils", "apt": "binutils"},
    "objdump": {"pkg": "binutils", "apt": "binutils"},
    "strings": {"pkg": "binutils", "apt": "binutils"},
    "tsu": {"pkg": "tsu", "apt": None},
}


def is_termux():
    return "com.termux" in os.environ.get("PREFIX", "") or platform.machine() in ("aarch64", "armv7l") and os.path.isdir("/data/data/com.termux")


def present(tool):
    return shutil.which(tool) is not None


def status():
    return {t: present(t) for t in TOOLS}


def missing(needs):
    return [n for n in needs if not present(n)]


def install_cmd(tools):
    pkg_mgr = "pkg" if is_termux() else "sudo apt-get install -y"
    pkgs = sorted({TOOLS[t]["pkg"] if is_termux() else TOOLS[t]["apt"]
                   for t in tools if t in TOOLS and (TOOLS[t]["pkg"] if is_termux() else TOOLS[t]["apt"])})
    pips = sorted({TOOLS[t]["pip"] for t in tools if t in TOOLS and TOOLS[t].get("pip")})
    parts = []
    if pkgs:
        parts.append(f"{pkg_mgr} {' '.join(pkgs)}")
    if pips:
        parts.append(f"pip install {' '.join(pips)}")
    return " && ".join(parts)


def doctor():
    rows = []
    for tool, meta in sorted(TOOLS.items()):
        if meta.get("pip") and not meta.get("pkg"):
            ok = False
            try:
                __import__(tool)
                ok = True
            except Exception:
                ok = False
            rows.append((tool, ok, "python"))
        else:
            rows.append((tool, present(tool), meta.get("pkg") or meta.get("apt") or "-"))
    return rows
