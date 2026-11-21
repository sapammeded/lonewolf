# -*- coding: utf-8 -*-
"""Helper registrasi modul."""
MODULES = []


def mod(**meta):
    def deco(fn):
        meta["run"] = fn
        MODULES.append(meta)
        return fn
    return deco
