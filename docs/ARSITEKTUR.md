# Arsitektur

Tiga frontend (`ui/menu.py`, `core/console.py`, `cli.py`) semuanya memanggil
`core/runner.py`. Runner memvalidasi parameter, membangun `Ctx`, mendaftarkan job,
lalu menjalankan `META["run"](ctx)`.

## Kontrak modul

```python
META = {
    "name": "kategori.nama",      # wajib, unik
    "category": "recon",          # wajib, harus dari CATEGORIES
    "desc": "penjelasan singkat", # wajib
    "params": {"target": {"required": True, "desc": "..."}},
    "needs": ["nmap"],            # opsional, dicek sebelum jalan
    "root": False,                # opsional
    "offline": False,             # opsional, aman untuk selftest
}
def run(ctx): ...
