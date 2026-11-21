# -*- coding: utf-8 -*-
"""Pembacaan banner dari file, fallback internal."""
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[2]
BANNER_FILE = SCRIPT_DIR / "banner.txt"
LOGO_FILE = SCRIPT_DIR / "assets" / "logo.txt"

FALLBACK_BANNER = r"""
 _      ____  _   _ _____   __      _____  _____ _
| |    / __ \| \ | | ____|  \ \    / / _ \|  ___| |
| |   | |  | |  \| |  _|     \ \  / / | | | |_  | |
| |___| |__| | |\  | |___     \ \/ /| |_| |  _| | |___
|_____|\____/|_| \_|_____|     \__/  \___/|_|   |_____|
"""

FALLBACK_LOGO = r"""
   /\___/\
  ( o   o )
  (  =^=  )
   (  _  )
    \___/
"""


def asset(path: Path, fallback: str) -> str:
    try:
        if path.exists():
            t = path.read_text(errors="replace").rstrip("\n")
            if t.strip():
                return t
    except Exception:
        pass
    return fallback


def banner_text():
    return asset(BANNER_FILE, FALLBACK_BANNER)


def logo_text():
    return asset(LOGO_FILE, FALLBACK_LOGO)
