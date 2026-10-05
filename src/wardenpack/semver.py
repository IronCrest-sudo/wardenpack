"""Tiny semver subset: X.Y.Z versions; specs: '', 'latest', exact, ^, ~, and comma-joined >= > <= < ="""
from __future__ import annotations

import re

from .errors import UnsafeInput

_V = re.compile(r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})$")
_OP = re.compile(r"^(>=|<=|>|<|=|\^|~)?\s*(\d{1,6}(?:\.\d{1,6}){0,2})$")


def parse(v: str) -> tuple:
    m = _V.match(v or "")
    if not m:
        raise UnsafeInput(f"invalid version {v!r} (expected MAJOR.MINOR.PATCH)")
    return tuple(int(x) for x in m.groups())


def _pad(s: str) -> tuple:
    parts = [int(x) for x in s.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def matches(version: str, spec: str) -> bool:
    spec = (spec or "").strip()
    if spec in ("", "latest", "*"):
        return True
    v = parse(version)
    for clause in spec.split(","):
        m = _OP.match(clause.strip())
        if not m:
            raise UnsafeInput(f"invalid version spec {spec!r}")
        op, num = m.group(1) or "=", m.group(2)
        t = _pad(num)
        if op == "=":
            ok = v == t
        elif op == ">=":
            ok = v >= t
        elif op == ">":
            ok = v > t
        elif op == "<=":
            ok = v <= t
        elif op == "<":
            ok = v < t
        elif op == "^":
            upper = (t[0] + 1, 0, 0) if t[0] > 0 else ((0, t[1] + 1, 0) if t[1] > 0 else (0, 0, t[2] + 1))
            ok = t <= v < upper
        else:  # ~
            ok = t <= v < (t[0], t[1] + 1, 0)
        if not ok:
            return False
    return True
