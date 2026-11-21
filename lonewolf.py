#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==================================================================
#  LONE WOLF 2026 — OFFENSIVE SECURITY FRAMEWORK v3.0
#  Termux (Android, non-root) + Linux
#  python lonewolf.py            -> menu
#  python lonewolf.py console    -> console
#  python lonewolf.py run recon.dns target=example.com
# ==================================================================
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lw.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n  dibatalkan")
        sys.exit(130)
