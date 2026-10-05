"""Registry maintainer tooling: pin libraries, audit them, build and sign index.json.

Design for a low-maintenance, offline-signed registry:
  libraries/<id>.json   one reviewed file per library (PR-friendly, CODEOWNERS-friendly)
  revocations.json      signed-in entries that make clients refuse/flag a commit or version
  index.json            the ONLY file clients trust; signed by an offline Ed25519 key
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

from . import ed25519, safety
from .audit import audit_tree
from .core import _enforce_audit, _read_json, _write_json
from .errors import ProjectError, RegistryError
from .gitfetch import fetch
from .registry import SCHEMA, validate_signed, sign_index
from .scan import read_meta, scan


def keygen(path) -> str:
    """Create a private key file (hex seed, mode 0600, never overwritten); return the public key hex."""
    seed, pub = ed25519.generate_keypair()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    return pub.hex()


def _load_seed(path) -> bytes:
    try:
        seed = bytes.fromhex(Path(path).read_text().strip())
    except (OSError, ValueError):
        raise RegistryError(f"cannot read private key file {path}") from None
    if len(seed) != 32:
        raise RegistryError("private key file must hold a 32-byte hex seed")
    return seed


def init_registry(root, name: str) -> None:
    root = Path(root)
    safety.validate_lib_id(name)
    if (root / "registry.json").exists():
        raise ProjectError("registry.json already exists")
    (root / "libraries").mkdir(parents=True, exist_ok=True)
    _write_json(root / "registry.json", {"schema": SCHEMA, "name": name})
    (root / "revocations.json").write_text("[]\n")
    (root / "README.md").write_text(
        f"# {name} (Wardenpack registry)\n\n"
        "* `libraries/<id>.json` - one file per library, added with `warden maintain add-lib`.\n"
        "* `revocations.json` - `{\"id\": ..., \"commit\"|\"version\": ..., \"reason\": ...}` entries.\n"
        "* `index.json` - signed by the maintainer's OFFLINE key (`warden maintain build`). Never commit the key.\n"
        "* `.github/workflows/site.yml` - publishes the website to GitHub Pages. Set the repository variable\n"
        "  `WARDEN_PUBKEY` to your public key. The workflow never signs anything; pin actions by commit SHA.\n")
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "site.yml").write_text(_WORKFLOW)


_WORKFLOW = """name: site
on:
  push:
    branches: [main]
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # pin to a full commit SHA in production
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install wardenpack         # pin an exact, reviewed version
      - run: warden maintain check .        # pinned commits still hash identically
      - run: warden maintain site index.json --out _site --key "${{ vars.WARDEN_PUBKEY }}" --base-url "${{ vars.SITE_URL }}"
      - uses: actions/upload-pages-artifact@v3
        with: { path: _site }
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: github-pages
    steps:
      - uses: actions/deploy-pages@v4
"""


def _entry_path(root: Path, lib_id: str) -> Path:
    return root / "libraries" / f"{safety.validate_lib_id(lib_id)}.json"


def add_lib(root, lib_id: str, source: str, ref: Optional[str] = None, version: Optional[str] = None,
            game_version: Optional[str] = None, description: str = "", license_id: str = "",
            fail_on: str = "high", hosts=safety.DEFAULT_HOSTS, allow_local: bool = False) -> dict:
    root = Path(root)
    source = safety.validate_source(source, hosts, allow_local)
    ref = safety.validate_ref(ref) if ref else None
    with tempfile.TemporaryDirectory(prefix="warden-reg-") as tmp:
        stage = Path(tmp) / "src"
        commit = fetch(source, stage, ref=ref, allow_local=allow_local)
        meta = read_meta(stage)
        version = version or meta.get("version")
        game_version = game_version or meta.get("game_version")
        if not version or not game_version:
            raise RegistryError("version and game_version are required (flags, or in the library's warden.json)")
        from . import semver
        semver.parse(version)
        content = scan(stage)
        report = audit_tree(stage)
        _enforce_audit(report, fail_on)
        rec = {"version": version, "game_version": game_version, "commit": commit,
               "integrity": content.integrity(), "audit": report.counts()}
        if ref:
            rec["ref"] = ref
    path = _entry_path(root, lib_id)
    entry = _read_json(path) if path.exists() else {"id": lib_id, "source": source, "versions": []}
    if entry["source"] != source:
        raise RegistryError(f"'{lib_id}' is already registered with source {entry['source']}")
    for v in entry["versions"]:
        if v["version"] == version:
            if v["commit"] == commit and v["integrity"] == rec["integrity"]:
                return entry                                   # idempotent
            raise RegistryError(f"{lib_id} {version} already exists with a different commit - "
                                "published versions are immutable; bump the version")
    entry["versions"].append(rec)
    entry["versions"].sort(key=lambda v: semver.parse(v["version"]))
    if description:
        entry["description"] = description[:300]
    if license_id:
        entry["license"] = license_id[:60]
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(path, entry)
    return entry


def build(root, key_path, valid_days: int = 180, today: Optional[date] = None) -> dict:
    root = Path(root)
    meta = _read_json(root / "registry.json")
    today = today or date.today()
    libs = {}
    for p in sorted((root / "libraries").glob("*.json")):
        e = _read_json(p)
        if e.get("id") != p.stem:
            raise RegistryError(f"{p.name}: id does not match file name")
        libs[e["id"]] = {k: e[k] for k in ("source", "description", "license", "versions") if k in e}
    try:
        revs = json.loads((root / "revocations.json").read_text())
    except (OSError, ValueError):
        raise RegistryError("revocations.json is missing or invalid") from None
    previous = 0
    idx = root / "index.json"
    if idx.exists():
        previous = json.loads(idx.read_text())["signed"]["version"]
    signed = {"schema": SCHEMA, "name": meta["name"], "version": previous + 1,
              "created": today.isoformat(), "expires": (today + timedelta(days=valid_days)).isoformat(),
              "libraries": libs, "revocations": revs}
    validate_signed(signed)
    env = sign_index(signed, _load_seed(key_path))
    idx.write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    return signed


def check(root, hosts=safety.DEFAULT_HOSTS, allow_local: bool = False) -> list[str]:
    """CI check: every pinned commit must still exist and hash to the recorded integrity."""
    problems = []
    for p in sorted((Path(root) / "libraries").glob("*.json")):
        e = _read_json(p)
        for v in e["versions"]:
            with tempfile.TemporaryDirectory(prefix="warden-chk-") as tmp:
                try:
                    src = safety.validate_source(e["source"], hosts, allow_local)
                    fetch(src, Path(tmp) / "s", commit=v["commit"], allow_local=allow_local)
                    got = scan(Path(tmp) / "s").integrity()
                except Exception as ex:           # report, keep checking the rest
                    problems.append(f"{e['id']} {v['version']}: {ex}")
                    continue
            if got != v["integrity"]:
                problems.append(f"{e['id']} {v['version']}: content no longer matches recorded integrity")
    return problems
