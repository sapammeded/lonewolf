# -*- coding: utf-8 -*-
"""Primitif jaringan: tanpa dependensi eksternal."""
import ipaddress
import shutil
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.request


def have(binary):
    return shutil.which(binary) is not None


def my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def gateway():
    try:
        for line in open("/proc/net/route"):
            f = line.split()
            if f[1] == "00000000":
                return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
    except Exception:
        pass
    return None


def local_cidr():
    ip = my_ip()
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return ip + "/24"


def arp_table():
    out = {}
    try:
        for line in open("/proc/net/arp"):
            f = line.split()
            if len(f) >= 4 and f[3] != "00:00:00:00:00:00":
                out[f[0]] = f[3]
    except Exception:
        pass
    return out


def expand(target, limit=1024):
    if "/" in target:
        try:
            return [str(h) for _, h in zip(range(limit), ipaddress.ip_network(target, strict=False).hosts())]
        except Exception:
            return []
    return [target]


def resolve(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def ping(ip, wait=1):
    try:
        rc = subprocess.run(["ping", "-c", "1", "-W", str(wait), ip],
                            capture_output=True, timeout=wait + 2).returncode
        return rc == 0
    except Exception:
        return False


def tcp_open(ip, port, timeout=2.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, int(port)))
        return True
    except Exception:
        return False
    finally:
        s.close()


def grab_banner(ip, port, timeout=3.0, probe=b"\r\n"):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        try:
            s.sendall(probe)
        except Exception:
            pass
        data = s.recv(1024)
        s.close()
        return data.decode(errors="replace").strip()
    except Exception:
        return ""


def http_get(url, timeout=10, headers=None, redirect=True):
    hdrs = {"User-Agent": "Mozilla/5.0 (LW/3.0)"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler() if redirect else _NoRedirect()
    )
    try:
        r = opener.open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read() if hasattr(e, "read") else b""
    except Exception as e:
        return 0, {}, str(e).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


def tls_info(host, port=443, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert() or {}
                return {"version": s.version(), "cipher": s.cipher(),
                        "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                        "notAfter": cert.get("notAfter"), "subjectAltName": cert.get("subjectAltName")}
    except Exception as e:
        return {"error": str(e)}


def parallel(items, fn, threads=16):
    """Jalankan fn(item) paralel, kembalikan hasil non-None."""
    out = []
    lock = threading.Lock()

    def wrap(it):
        try:
            r = fn(it)
        except Exception:
            r = None
        if r is not None:
            with lock:
                out.append(r)

    batch = max(1, int(threads))
    for i in range(0, len(items), batch):
        ts = [threading.Thread(target=wrap, args=(x,), daemon=True) for x in items[i:i + batch]]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    return out
