#!/usr/bin/env bash
# LONE WOLF 2026 installer — Termux & Linux
set -u
cd "$(dirname "$0")"

if [ -n "${PREFIX:-}" ] && [ -d "$PREFIX" ] && echo "$PREFIX" | grep -q termux; then
  PKG="pkg"
  DEPS="python nmap whois dnsutils openssl-tool android-tools termux-api bluez-utils netcat-openbsd tcpdump binutils"
else
  PKG="apt-get"
  DEPS="python3 python3-pip nmap whois dnsutils openssl netcat-openbsd tcpdump binutils gcc"
  command -v sudo >/dev/null && SUDO="sudo" || SUDO=""
fi
SUDO="${SUDO:-}"

echo "[*] dependensi dasar"
$SUDO $PKG update -y >/dev/null 2>&1 || true
$SUDO $PKG install -y $DEPS >/dev/null 2>&1 || echo "[!] sebagian paket gagal, lanjut"

echo "[*] dependensi python"
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install -r requirements.txt || echo "[!] pip sebagian gagal"

chmod +x lonewolf.py pack.sh uninstall.sh
mkdir -p "$HOME/.lw/workspaces" "$HOME/.lw/out" "$HOME/.lw/plugins"

echo "[*] verifikasi"
python3 -m py_compile lonewolf.py || exit 1
python3 lonewolf.py selftest || echo "[!] selftest tidak lolos penuh"

echo
echo "[+] selesai. jalankan: python3 lonewolf.py"
echo "[i] opsional root: pkg install root-repo && pkg install tsu"
echo "[i] opsional alat berat: pkg install hydra sqlmap exploitdb aircrack-ng"
