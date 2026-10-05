"""Static inspection of a fetched library BEFORE anything touches the project."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import safety
from .errors import ScanError, UnsafeInput

MAX_FILES = 5000
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024
ROOTS = ("data", "assets")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def value_key(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


@dataclass
class LibraryContent:
    files: dict[str, Path] = field(default_factory=dict)     # rel -> source file (copied verbatim)
    hashes: dict[str, str] = field(default_factory=dict)     # rel -> sha256
    tags: dict[str, list] = field(default_factory=dict)      # rel -> values to merge (minecraft tags)
    skipped: list[str] = field(default_factory=list)

    def integrity(self) -> str:
        h = hashlib.sha256()
        for rel in sorted(self.hashes):
            h.update(f"F {rel} {self.hashes[rel]}\n".encode())
        for rel in sorted(self.tags):
            for key in sorted(value_key(v) for v in self.tags[rel]):
                h.update(f"T {rel} {key}\n".encode())
        return h.hexdigest()

    def namespaces(self) -> list[str]:
        out = set()
        for rel in self.files:
            parts = rel.split("/")
            out.add(f"{parts[0]}/{parts[1]}")
        return sorted(out)


def read_meta(root: Path) -> dict:
    """Optional library warden.json: we only look at game_version and version."""
    p = root / "warden.json"
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 100_000:
        return {}
    try:
        data = json.loads(p.read_text("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    out = {}
    if isinstance(data, dict):
        for k in ("game_version", "version"):
            if isinstance(data.get(k), str):
                out[k] = data[k]
    return out


def _parse_tag(path: Path, rel: str) -> list:
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ScanError(f"{rel}: invalid JSON tag ({e})") from None
    if not isinstance(doc, dict) or set(doc) - {"values", "replace"}:
        raise ScanError(f"{rel}: unexpected keys in tag file")
    if doc.get("replace") not in (None, False):
        raise ScanError(f"{rel}: 'replace': true would wipe other entries of a vanilla tag")
    vals = doc.get("values", [])
    if not isinstance(vals, list):
        raise ScanError(f"{rel}: 'values' must be a list")
    for v in vals:
        ok = isinstance(v, str) or (isinstance(v, dict) and isinstance(v.get("id"), str))
        if not ok:
            raise ScanError(f"{rel}: malformed tag value {v!r}")
    return vals


def scan(root: Path) -> LibraryContent:
    root = Path(root)
    out = LibraryContent()
    total = 0
    for entry in sorted(os.listdir(root)):
        if entry not in ROOTS and entry != ".git":
            out.skipped.append(entry)                    # README, LICENSE, pack.mcmeta, ... never copied
    for top in ROOTS:
        base = root / top
        if not os.path.lexists(base):
            continue
        if os.path.islink(base) or not base.is_dir():
            raise ScanError(f"'{top}' must be a real directory (symlink or file found)")
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for name in sorted(dirnames + filenames):
                full = Path(dirpath) / name
                rel = full.relative_to(root).as_posix()
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    raise ScanError(f"{rel}: symlinks are not allowed")
                if name.startswith("."):
                    out.skipped.append(rel)
                    if stat.S_ISDIR(st.st_mode):
                        dirnames[:] = [d for d in dirnames if d != name]
                    continue
                try:
                    safety.validate_rel(rel)
                except UnsafeInput as e:
                    raise ScanError(f"{rel}: {e}") from None
                if stat.S_ISDIR(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise ScanError(f"{rel}: not a regular file")
                if st.st_size > MAX_FILE:
                    raise ScanError(f"{rel}: file larger than {MAX_FILE >> 20} MiB")
                total += st.st_size
                if total > MAX_TOTAL or len(out.files) >= MAX_FILES:
                    raise ScanError("library exceeds size/file-count limits")
                _classify(root, full, rel, st.st_size, out)
    if not out.files and not out.tags:
        raise ScanError("library contains no data/ or assets/ content")
    return out


def _classify(root: Path, full: Path, rel: str, size: int, out: LibraryContent) -> None:
    parts = rel.split("/")
    if len(parts) < 3:
        raise ScanError(f"{rel}: files must live inside data/<namespace>/ or assets/<namespace>/")
    try:
        safety.validate_namespace(parts[1])
    except UnsafeInput as e:
        raise ScanError(f"{rel}: {e}") from None
    if parts[1] == "minecraft":
        is_tag = parts[0] == "data" and parts[2] == "tags" and rel.endswith(".json") and len(parts) >= 5
        if not is_tag:
            raise ScanError(f"{rel}: libraries may not override vanilla 'minecraft' resources "
                            "(only data/minecraft/tags/**.json is merged)")
        out.tags[rel] = _parse_tag(full, rel)
        return
    out.files[rel] = full
    out.hashes[rel] = sha256_file(full)
