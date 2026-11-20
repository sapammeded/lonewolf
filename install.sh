#!/data/data/com.termux/files/usr/bin/bash
set -e
echo "[*] update paket..."
pkg update -y >/dev/null 2>&1 || true
echo "[*] install dependensi..."
pkg install -y python nmap whois dnsutils openssl-tool android-tools termux-api \
  bluez-utils 2>/dev/null || \
  pkg install -y python nmap whois dnsutils openssl-tool android-tools termux-api
echo "[*] install modul python..."
pip install --upgrade pip >/dev/null 2>&1 || true
pip install -r requirements.txt
chmod +x lonewolf.py
echo
echo "[+] selesai. jalankan: python lonewolf.py"
echo "[i] opsional root: pkg install root-repo && pkg install tsu"
