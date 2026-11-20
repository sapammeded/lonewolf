# Detail Modul

## 1. Reconnaissance & Footprinting
whois, DNS record, reverse lookup, HTTP header, deteksi teknologi.

## 2. Network Scanning
nmap -sn untuk host discovery, nmap -sT -F untuk port. Fallback: ARP table + ping sweep.

## 3. Vulnerability Assessment
Pencarian CVE via NVD API, audit header keamanan, nikto, whatweb.

## 4. Exploitation Frameworks
searchsploit, generator payload msfvenom (apk/elf/python/bash), msfconsole, daftar payload lokal.

## 5. Password Cracking
Identifikasi tipe hash, john, hashcat, generator wordlist.

## 6. Social Engineering Suite
Server phishing lokal + tangkap kredensial, redirect setelah submit, siap dipasangkan cloudflared.

## 7. Web Application Hacking
Bruteforce direktori (threaded), sqlmap, uji refleksi XSS, fuzz parameter.

## 8. Privilege Escalation
Enumerasi su/tsu, kernel, SELinux, direktori writable, SUID, ro.debuggable.

## 9. Wireless Network Auditing
Scan SSID sekitar (termux-api), info koneksi, analisa keamanan band/kekuatan sinyal.

## 10. Bluetooth Popup Spam
Advertising BLE dengan nama device populer berotasi lewat `hcitool cmd` sehingga
muncul notifikasi pairing di HP sekitar.

## 11. MITM
ARP poison dua arah + redirect iptables ke mitmproxy (root), atau mode proxy eksplisit
dengan sertifikat mitm.it (non-root). Termasuk host discovery dan capture pcap.

## 12. Wi-Fi Broadcast Message
HTTP server yang menyajikan halaman popup berisi kalimat bebas, dikombinasikan dengan
ARP poison + redirect port 80 agar semua device sejaringan otomatis terbuka.

## Kustomisasi banner
`banner.txt` dan `assets/logo.txt` dibaca setiap kali menu dirender. Ganti bebas.
