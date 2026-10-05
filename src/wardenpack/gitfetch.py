"""Hardened git access: no hooks, no ext:: transport, no prompts, nothing executed."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from .errors import FetchError
from .safety import validate_commit, validate_ref

TIMEOUT = 180


def _env(allow_local: bool) -> dict:
    keep = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "SSH_AUTH_SOCK", "LANG")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(
        GIT_ALLOW_PROTOCOL="https:ssh" + (":file" if allow_local else ""),
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_LFS_SKIP_SMUDGE="1",
        GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes",
    )
    return env


def _git(args, cwd: Path, env: dict) -> str:
    cmd = [
        "git",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.ext.allow=never",
        "-c", "transfer.fsckObjects=true",
        "-c", "advice.detachedHead=false",
        *args,
    ]
    try:
        res = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except FileNotFoundError:
        raise FetchError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise FetchError(f"git timed out after {TIMEOUT}s") from None
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip().replace("\n", " ")[:400]
        raise FetchError(f"git {args[0]} failed: {msg}")
    return res.stdout.strip()


def _rmtree(path: Path) -> None:
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=onerror)


def fetch(url: str, dest: Path, ref: str | None = None, commit: str | None = None,
          allow_local: bool = False) -> str:
    """Shallow-fetch exactly one revision into `dest` (no .git left behind).

    Returns the full commit id. When `commit` is given the fetched revision must match it.
    """
    if commit:
        validate_commit(commit)
    if ref:
        validate_ref(ref)
    env = _env(allow_local)
    dest.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q"], dest, env)
    target = commit or ref or "HEAD"
    _git(["fetch", "-q", "--depth", "1", "--no-tags", "--", url, target], dest, env)
    fetched = _git(["rev-parse", "FETCH_HEAD^{commit}"], dest, env).lower()
    if commit and fetched != commit:
        raise FetchError(f"server returned {fetched}, expected pinned commit {commit}")
    _git(["checkout", "-q", "--detach", "FETCH_HEAD"], dest, env)
    _rmtree(dest / ".git")
    return fetched
