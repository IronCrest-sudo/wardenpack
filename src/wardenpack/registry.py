"""Signed registry index: verification, freshness, rollback protection, revocation, resolution."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from . import ed25519, safety, semver
from .errors import RegistryError, RollbackError, StaleRegistry, UnsafeInput

SCHEMA = 1
MAX_INDEX = 2_000_000
TIMEOUT = 30
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEYID = re.compile(r"^[0-9a-f]{16}$")
_SIG = re.compile(r"^[0-9a-f]{128}$")


def canonical(obj) -> bytes:
    """Deterministic bytes that are signed. Independent of how the file is pretty-printed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_index(signed: dict, seed: bytes) -> dict:
    pub = ed25519.public_from_seed(seed)
    return {"signed": signed,
            "signatures": [{"keyid": ed25519.keyid(pub), "sig": ed25519.sign(seed, canonical(signed)).hex()}]}


# ----------------------------------------------------------------------- fetching
class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise RegistryError("registry redirected to a non-https URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_location(loc: str) -> str:
    """Registry index location: an absolute local file path or an https:// URL."""
    if not isinstance(loc, str) or not loc or len(loc) > 300 or re.search(r"[\x00-\x20\x7f\\]", loc) and not os.path.isabs(loc):
        raise UnsafeInput("invalid registry location")
    if os.path.isabs(loc):
        return loc
    p = urlsplit(loc)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise UnsafeInput("registry URL must be https:// without credentials")
    return loc


def fetch_bytes(location: str) -> bytes:
    validate_location(location)
    try:
        if os.path.isabs(location):
            with open(location, "rb") as f:
                data = f.read(MAX_INDEX + 1)
        else:
            opener = urllib.request.build_opener(_HttpsOnly)
            req = urllib.request.Request(location, headers={"User-Agent": "wardenpack"})
            with opener.open(req, timeout=TIMEOUT) as resp:
                data = resp.read(MAX_INDEX + 1)
    except (OSError, urllib.error.URLError) as e:
        raise RegistryError(f"cannot fetch registry index: {e}") from None
    if len(data) > MAX_INDEX:
        raise RegistryError("registry index is too large")
    return data


# ----------------------------------------------------------------------- validation
def _date(s, what):
    try:
        return date.fromisoformat(s)
    except (TypeError, ValueError):
        raise RegistryError(f"index: bad {what} date {s!r}") from None


def validate_signed(signed) -> None:
    if not isinstance(signed, dict) or signed.get("schema") != SCHEMA:
        raise RegistryError("index: unsupported schema")
    if not isinstance(signed.get("name"), str) or not isinstance(signed.get("version"), int) or signed["version"] < 1:
        raise RegistryError("index: bad name/version")
    _date(signed.get("created"), "created")
    _date(signed.get("expires"), "expires")
    libs = signed.get("libraries")
    if not isinstance(libs, dict) or len(libs) > 5000:
        raise RegistryError("index: bad libraries")
    for lib_id, e in libs.items():
        try:
            safety.validate_lib_id(lib_id)
        except UnsafeInput as ex:
            raise RegistryError(f"index: {ex}") from None
        if not isinstance(e, dict) or not isinstance(e.get("source"), str) or not isinstance(e.get("versions"), list) \
                or len(e["versions"]) > 500:
            raise RegistryError(f"index: malformed entry '{lib_id}'")
        for v in e["versions"]:
            ok = (isinstance(v, dict) and isinstance(v.get("version"), str) and isinstance(v.get("game_version"), str)
                  and _HEX40.match(str(v.get("commit"))) and _HEX64.match(str(v.get("integrity"))))
            if not ok:
                raise RegistryError(f"index: malformed version in '{lib_id}'")
            semver.parse(v["version"])
    revs = signed.get("revocations", [])
    if not isinstance(revs, list) or not all(isinstance(r, dict) and isinstance(r.get("id"), str) for r in revs):
        raise RegistryError("index: bad revocations")


def verify_index(raw: bytes, trusted_keys: list, threshold: int = 1, today: Optional[date] = None,
                 last_version: Optional[int] = None, allow_stale: bool = False) -> dict:
    """Return the signed payload only if enough trusted keys signed it and it is fresh/not rolled back."""
    try:
        env = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise RegistryError("index is not valid JSON") from None
    if not isinstance(env, dict) or "signed" not in env or not isinstance(env.get("signatures"), list):
        raise RegistryError("index: not a signed envelope")
    by_id = {}
    for k in trusted_keys:
        pub = bytes.fromhex(k)
        by_id[ed25519.keyid(pub)] = pub
    msg = canonical(env["signed"])
    good = set()
    for s in env["signatures"]:
        if not (isinstance(s, dict) and _KEYID.match(str(s.get("keyid"))) and _SIG.match(str(s.get("sig")))):
            continue
        pub = by_id.get(s["keyid"])
        if pub is not None and ed25519.verify(pub, msg, bytes.fromhex(s["sig"])):
            good.add(s["keyid"])
    if len(good) < threshold:
        raise RegistryError(f"index signature check failed: {len(good)} valid trusted signature(s), "
                            f"{threshold} required - wrong key, tampered index, or unsigned")
    signed = env["signed"]
    validate_signed(signed)
    if last_version is not None and signed["version"] < last_version:
        raise RollbackError(f"index version {signed['version']} is older than the version already seen "
                            f"({last_version}) - possible rollback attack or stale mirror")
    today = today or datetime.now(timezone.utc).date()
    if _date(signed["expires"], "expires") < today and not allow_stale:
        raise StaleRegistry(f"index expired on {signed['expires']}; the maintainer has not re-signed it. "
                            "Existing locked installs are unaffected. Use --allow-stale to resolve anyway "
                            "(you then lose protection against missed revocations/updates).")
    return signed


# ----------------------------------------------------------------------- queries
def revoked_reason(signed: dict, lib_id: str, version: Optional[str] = None, commit: Optional[str] = None):
    for r in signed.get("revocations", []):
        if r.get("id") != lib_id:
            continue
        if (r.get("commit") and r["commit"] == commit) or (r.get("version") and r["version"] == version):
            return str(r.get("reason", "no reason given"))[:200]
    return None


def resolve(signed: dict, lib_id: str, spec: str, game_version: Optional[str], ignore_game_version=False):
    entry = signed["libraries"].get(lib_id)
    if entry is None:
        raise RegistryError(f"'{lib_id}' is not in registry '{signed['name']}'")
    cands, skipped = [], []
    for v in entry["versions"]:
        if not semver.matches(v["version"], spec):
            continue
        if game_version and not ignore_game_version and v["game_version"] != game_version:
            skipped.append(f"{v['version']} (game {v['game_version']})")
            continue
        why = revoked_reason(signed, lib_id, v["version"], v["commit"])
        if why:
            skipped.append(f"{v['version']} (REVOKED: {why})")
            continue
        cands.append(v)
    if not cands:
        have = ", ".join(f"{v['version']}/{v['game_version']}" for v in entry["versions"]) or "none"
        extra = f"; skipped: {', '.join(skipped)}" if skipped else ""
        raise RegistryError(f"no usable version of '{lib_id}' for spec {spec or 'latest'!r} "
                            f"(project game {game_version}). Available: {have}{extra}")
    return entry, max(cands, key=lambda v: semver.parse(v["version"]))
