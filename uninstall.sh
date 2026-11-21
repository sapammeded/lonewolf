#!/usr/bin/env bash
read -r -p "hapus juga ~/.lw (workspace+hasil)? [y/N] " a
rm -f "$HOME"/.lw/current_ws 2>/dev/null
if [ "${a:-n}" = "y" ]; then rm -rf "$HOME/.lw"; echo "[+] data dihapus."; else echo "[+] data dipertahankan."; fi
echo "[+] selesai."
