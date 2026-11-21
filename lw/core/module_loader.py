# -*- coding: utf-8 -*-
"""Registry modul dinamis dengan validasi manifest."""
import importlib

CATEGORIES = {
    "recon": "Reconnaissance & Footprinting",
    "network": "Network Scanning & Mapping",
    "vuln": "Vulnerability Assessment",
    "exploit": "Exploitation & Payload",
    "web": "Web Application Hacking",
    "auth": "Password & Authentication",
    "privesc": "Privilege Escalation",
    "wireless": "Wireless Auditing",
    "bluetooth": "Bluetooth",
    "mitm": "MITM & Traffic Analysis",
    "proto": "Protocol Analysis",
    "binary": "Binary Analysis & RE",
    "se": "Social Engineering",
    "broadcast": "Network Broadcast",
}

REQUIRED_META = ("name", "category", "desc", "run")
_registry = {}
_errors = []


def _validate(meta):
    for k in REQUIRED_META:
        if k not in meta:
            return f"meta '{k}' hilang"
    if meta["category"] not in CATEGORIES:
        return f"kategori tidak dikenal: {meta['category']}"
    if not callable(meta["run"]):
        return "run tidak callable"
    if meta["name"] in _registry:
        return f"nama duplikat: {meta['name']}"
    for key, spec in (meta.get("params") or {}).items():
        if not isinstance(spec, dict):
            return f"param '{key}' bukan dict"
    return None


def load_all():
    _registry.clear()
    _errors.clear()
    from ..modules import CATEGORY_MODULES
    for mod_path in CATEGORY_MODULES:
        try:
            m = importlib.import_module(f"lw.modules.{mod_path}")
            importlib.reload(m)
        except Exception as e:
            _errors.append(f"{mod_path}: {e}")
            continue
        for meta in getattr(m, "MODULES", []):
            err = _validate(meta)
            if err:
                _errors.append(f"{mod_path}/{meta.get('name','?')}: {err}")
                continue
            meta.setdefault("params", {})
            meta.setdefault("needs", [])
            meta.setdefault("root", False)
            meta.setdefault("offline", False)
            meta["source"] = f"builtin:{mod_path}"
            _registry[meta["name"]] = meta
    return _registry


def registry():
    if not _registry:
        load_all()
    return _registry


def register(meta, origin="plugin"):
    err = _validate(meta)
    if err:
        return err
    meta.setdefault("params", {})
    meta.setdefault("needs", [])
    meta.setdefault("root", False)
    meta.setdefault("offline", False)
    meta["source"] = origin
    _registry[meta["name"]] = meta
    return None


def unregister(name):
    return _registry.pop(name, None)


def get(name):
    return registry().get(name)


def by_category(cat):
    return [m for m in registry().values() if m["category"] == cat]


def search(term):
    term = term.lower()
    return [m for m in registry().values()
            if term in m["name"].lower() or term in m["desc"].lower()]


def errors():
    registry()
    return list(_errors)


def stats():
    reg = registry()
    per = {}
    for m in reg.values():
        per[m["category"]] = per.get(m["category"], 0) + 1
    return {"total": len(reg), "per_category": per, "errors": len(_errors)}
