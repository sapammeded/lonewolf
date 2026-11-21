# -*- coding: utf-8 -*-
"""Multi-language execution engine: python/bash/sh/node/php/ruby/perl/go/c/cpp/rust/java."""
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

LANGS = {
    "python": {"ext": ".py", "run": ["python3", "-u"], "need": "python3"},
    "bash": {"ext": ".sh", "run": ["bash"], "need": "bash"},
    "sh": {"ext": ".sh", "run": ["sh"], "need": "sh"},
    "node": {"ext": ".js", "run": ["node"], "need": "node"},
    "php": {"ext": ".php", "run": ["php"], "need": "php"},
    "ruby": {"ext": ".rb", "run": ["ruby"], "need": "ruby"},
    "perl": {"ext": ".pl", "run": ["perl"], "need": "perl"},
    "go": {"ext": ".go", "build": ["go", "build", "-o"], "need": "go"},
    "c": {"ext": ".c", "build": ["gcc", "-O2", "-o"], "need": "gcc"},
    "cpp": {"ext": ".cpp", "build": ["g++", "-O2", "-o"], "need": "g++"},
    "rust": {"ext": ".rs", "build": ["rustc", "-O", "-o"], "need": "rustc"},
    "java": {"ext": ".java", "java": True, "need": "javac"},
}


@dataclass
class ExecResult:
    lang: str
    rc: int
    stdout: str
    stderr: str
    elapsed: float
    binary: str = ""
    source: str = ""

    @property
    def ok(self):
        return self.rc == 0

    def text(self, limit=6000):
        body = (self.stdout or "") + ("\n[stderr]\n" + self.stderr if self.stderr else "")
        return body[:limit]


def toolchain(lang):
    spec = LANGS.get(lang)
    if not spec:
        return None
    return shutil.which(spec["need"])


def available():
    return sorted(l for l in LANGS if toolchain(l))


def run_source(lang, code, workdir, timeout=120, argv=None):
    """Tulis source, kompilasi bila perlu, eksekusi, kembalikan ExecResult."""
    spec = LANGS.get(lang)
    if not spec:
        return ExecResult(lang, 127, "", f"bahasa tidak didukung: {lang}", 0.0)
    if not toolchain(lang):
        return ExecResult(lang, 127, "", f"toolchain tidak ada: {spec['need']}", 0.0)

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    stem = f"lw_{int(time.time() * 1000)}"
    src = workdir / (stem + spec["ext"])
    src.write_text(code)

    t0 = time.time()
    try:
        if "build" in spec:
            out = workdir / stem
            cmd = spec["build"] + [str(out), str(src)]
            b = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
            if b.returncode != 0:
                return ExecResult(lang, b.returncode, b.stdout, b.stderr, time.time() - t0, source=str(src))
            cmd = [str(out)] + (argv or [])
        elif spec.get("java"):
            b = subprocess.run(["javac", str(src)], capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            if b.returncode != 0:
                return ExecResult(lang, b.returncode, b.stdout, b.stderr, time.time() - t0, source=str(src))
            cmd = ["java", "-cp", str(workdir), stem] + (argv or [])
        else:
            cmd = spec["run"] + [str(src)] + (argv or [])

        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace", cwd=str(workdir))
        return ExecResult(lang, p.returncode, p.stdout, p.stderr, time.time() - t0,
                          binary=cmd[0], source=str(src))
    except subprocess.TimeoutExpired:
        return ExecResult(lang, 124, "", f"timeout {timeout}s", time.time() - t0, source=str(src))
    except Exception as e:
        return ExecResult(lang, 1, "", str(e), time.time() - t0, source=str(src))


def detect_lang(path):
    ext = Path(path).suffix.lower()
    for lang, spec in LANGS.items():
        if spec["ext"] == ext:
            return lang
    return None
