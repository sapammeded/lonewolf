#!/usr/bin/env bash
# Membuat ZIP distribusi final (tanpa __pycache__ dan data lokal)
set -e
cd "$(dirname "$0")"
OUT="lonewolf-2026-$(date +%Y%m%d-%H%M).zip"
python3 - "$OUT" <<'PY'
import sys, zipfile, pathlib
out = sys.argv[1]
skip = {"__pycache__", ".git", ".lw"}
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in pathlib.Path(".").rglob("*"):
        if any(s in p.parts for s in skip) or p.suffix == ".zip":
            continue
        if p.is_file():
            z.write(p, p.as_posix())
print("dibuat:", out)
PY
sha256sum "$OUT" > "$OUT.sha256" 2>/dev/null || true
echo "[+] $OUT"
