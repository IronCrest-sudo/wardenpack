"""Input validation. Everything that reaches git or the filesystem passes here first."""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from .errors import UnsafeInput

DEFAULT_HOSTS = frozenset({"github.com", "codeberg.org", "gitlab.com"})

_LIB_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_NAMESPACE = re.compile(r"^[a-z0-9_.-]{1,64}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,99}$")
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")      # control chars, space, backslash
_SEGMENT = re.compile(r"^[A-Za-z0-9_.+-]+$")
MAX_REL_LEN = 240
_WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|conin\$|conout\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(\..*)?$", re.I)


def windows_hazard(rel: str):
    """Why this path misbehaves on Windows (reserved device names, trailing dot/space, ':'/ADS), or None."""
    for seg in rel.split("/"):
        if not seg:
            continue
        if _WIN_RESERVED.match(seg):
            return f"'{seg}' is a reserved Windows device name"
        if seg.endswith((".", " ")) and seg not in (".", ".."):
            return f"'{seg}' ends with a dot/space (Windows silently renames it, e.g. 'x.exe.' -> 'x.exe')"
        if ":" in seg:
            return f"'{seg}' contains ':' (NTFS alternate data stream)"
    return None


def validate_lib_id(name: str) -> str:
    if not isinstance(name, str) or not _LIB_ID.match(name):
        raise UnsafeInput(f"invalid library name {name!r} (use a-z 0-9 _ . -, max 64 chars)")
    return name


def validate_namespace(ns: str) -> str:
    if not isinstance(ns, str) or not _NAMESPACE.match(ns):
        raise UnsafeInput(f"invalid namespace {ns!r} (use a-z 0-9 _ . -)")
    return ns


def validate_ref(ref: str) -> str:
    bad = (
        not isinstance(ref, str)
        or not _REF.match(ref)
        or ".." in ref
        or "//" in ref
        or "@{" in ref
        or ref.endswith(("/", ".lock", "."))
    )
    if bad:
        raise UnsafeInput(f"invalid git ref {ref!r}")
    return ref


def validate_commit(commit: str) -> str:
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise UnsafeInput(f"invalid commit id {commit!r} (expected 40 hex chars)")
    return commit


def validate_source(url: str, allowed_hosts, allow_local: bool = False) -> str:
    """Accept only https:// or ssh:// URLs on allow-listed hosts.

    Rejected on purpose: option-looking values ('-x'), git's ext::/fd:: transports,
    http://, file://, credentials embedded in https URLs, ports, queries, '..'.
    """
    if not isinstance(url, str) or not url or len(url) > 300:
        raise UnsafeInput("source URL is empty or too long")
    if url.startswith("-"):
        raise UnsafeInput("source URL must not start with '-'")
    if allow_local and os.path.isabs(url) and not _BAD_CHARS.search(url):
        return url                                   # test/offline use only, opt-in
    if _BAD_CHARS.search(url):
        raise UnsafeInput("source URL contains whitespace/control characters")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "ssh"):
        raise UnsafeInput(f"unsupported scheme in {url!r}: only https:// and ssh:// are allowed")
    if parts.password or (parts.scheme == "https" and parts.username):
        raise UnsafeInput("credentials in URLs are not allowed")
    if parts.scheme == "ssh" and parts.username not in (None, "git"):
        raise UnsafeInput("ssh URLs must use the 'git' user")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeInput("invalid port in URL") from None
    if port is not None:
        raise UnsafeInput("custom ports are not allowed")
    if parts.query or parts.fragment:
        raise UnsafeInput("query strings/fragments are not allowed in source URLs")
    host = (parts.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise UnsafeInput(
            f"host {host!r} is not allow-listed (allowed: {', '.join(sorted(allowed_hosts))}); "
            "add it with --allow-host or 'allowed_hosts' in warden.json"
        )
    segs = [s for s in parts.path.split("/") if s]
    if len(segs) < 2 or any(s in (".", "..") for s in segs):
        raise UnsafeInput("source URL must look like https://host/owner/repo")
    return url


def name_from_source(url: str) -> str:
    last = [s for s in url.rstrip("/").split("/") if s][-1]
    if last.endswith(".git"):
        last = last[:-4]
    return validate_lib_id(last.lower())


def validate_rel(rel: str) -> str:
    """A project-relative POSIX path that cannot escape the project."""
    if not isinstance(rel, str) or not rel or len(rel) > MAX_REL_LEN:
        raise UnsafeInput(f"invalid path {rel!r}")
    if rel.startswith("/") or _BAD_CHARS.search(rel) or re.match(r"^[A-Za-z]:", rel):
        raise UnsafeInput(f"invalid path {rel!r}")
    for seg in rel.split("/"):
        if seg in ("", ".", "..") or not _SEGMENT.match(seg):
            raise UnsafeInput(f"invalid path segment in {rel!r}")
    hazard = windows_hazard(rel)
    if hazard:
        raise UnsafeInput(f"unsafe path {rel!r}: {hazard}")
    return rel
