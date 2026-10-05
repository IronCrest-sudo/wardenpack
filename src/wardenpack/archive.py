"""Safe zip extraction for auditing downloaded datapacks (never trusts the archive)."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .audit import Finding
from .errors import ScanError

MAX_ENTRIES = 20000
MAX_FILE = 50 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024


def extract_zip(zpath, dest: Path) -> list:
    """Extract regular files only. Traversal/symlink/odd-name entries are skipped and reported."""
    findings: list = []
    dest.mkdir(parents=True, exist_ok=True)
    base = dest.resolve()
    try:
        zf = zipfile.ZipFile(zpath)
    except (zipfile.BadZipFile, OSError) as e:
        raise ScanError(f"cannot open zip: {e}") from None
    total = 0
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ScanError("zip has too many entries")
        for info in infos:
            name = info.filename.replace("\\", "/")
            if info.is_dir():
                continue
            problem = None
            if re.search(r"[\x00-\x1f]", name):
                problem = ("ZIP-NAME", "control characters in entry name")
            elif name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
                problem = ("ZIP-TRAVERSAL", "entry would be extracted outside the pack folder")
            elif (info.external_attr >> 16) & 0o170000 == 0o120000:
                problem = ("ZIP-SYMLINK", "symbolic link entry")
            if problem is None:
                target = (base / name).resolve()
                if base not in target.parents:
                    problem = ("ZIP-TRAVERSAL", "entry would be extracted outside the pack folder")
            if problem:
                findings.append(Finding(problem[0], "high", name[:120].encode("ascii", "replace").decode(),
                                        0, problem[1], "", True))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info) as src, open(target, "wb") as out:
                    for chunk in iter(lambda: src.read(1 << 16), b""):
                        written += len(chunk)
                        total += len(chunk)
                        if written > MAX_FILE or total > MAX_TOTAL:
                            raise ScanError("zip expands beyond size limits (possible zip bomb)")
                        out.write(chunk)
            except RuntimeError:
                raise ScanError("encrypted zip entries are not supported") from None
    return findings


def find_pack_root(root: Path) -> Path:
    """A zip often wraps the pack in one folder; descend into it."""
    if (root / "data").is_dir() or (root / "pack.mcmeta").exists():
        return root
    subs = [d for d in root.iterdir() if d.is_dir()]
    if len(subs) == 1 and ((subs[0] / "data").is_dir() or (subs[0] / "pack.mcmeta").exists()):
        return subs[0]
    return root
