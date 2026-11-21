# -*- coding: utf-8 -*-
"""Plugin pengguna dari ~/.lw/plugins/*.py — kontrak sama dengan modul bawaan."""
import importlib.util
import sys
from . import module_loader
from .config import PLUGIN_DIR

PREFIX = "plugin."


def _load_file(path):
    spec = importlib.util.spec_from_file_location(f"lwplugin_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_plugins():
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    report = []
    for path in sorted(PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            mod = _load_file(path)
        except Exception as e:
            report.append((path.name, f"import gagal: {e}"))
            continue
        metas = getattr(mod, "MODULES", None)
        if metas is None and hasattr(mod, "META") and hasattr(mod, "run"):
            metas = [dict(mod.META, run=mod.run)]
        if not metas:
            report.append((path.name, "tidak ada MODULES/META"))
            continue
        for meta in metas:
            meta = dict(meta)
            if not meta.get("name", "").startswith(PREFIX):
                meta["name"] = PREFIX + meta.get("name", path.stem)
            err = module_loader.register(meta, origin=f"plugin:{path.name}")
            report.append((path.name, err or "ok"))
    return report


def scaffold(name):
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    p = PLUGIN_DIR / f"{name}.py"
    p.write_text(f'''# -*- coding: utf-8 -*-
META = {{
    "name": "{name}",
    "category": "recon",
    "desc": "plugin contoh {name}",
    "params": {{"target": {{"required": True, "desc": "target"}}}},
}}
def run(ctx):
    ctx.out("hello dari plugin " + ctx.p("target"))
    ctx.finding("plugin jalan", "info", module="{name}")
''')
    return p
