"""Project state (warden.json + warden.lock) and the install/remove/verify engine."""
from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import safety
from .archive import extract_zip, find_pack_root
from .audit import SEV, AuditReport, audit_tree, format_finding
from .errors import (Aborted, AuditError, ConflictError, IntegrityError, ProjectError, UnsafeInput)
from .gitfetch import fetch
from . import registry as reg
from .scan import LibraryContent, read_meta, scan, sha256_file, value_key

SCHEMA = 1
MAX_JSON = 1_000_000
Confirm = Optional[Callable[[list], bool]]


# ----------------------------------------------------------------- json helpers
def _read_json(path: Path) -> dict:
    if path.stat().st_size > MAX_JSON:
        raise ProjectError(f"{path.name} is unreasonably large")
    try:
        data = json.loads(path.read_text("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise ProjectError(f"{path.name}: invalid JSON ({type(e).__name__})") from None
    if not isinstance(data, dict):
        raise ProjectError(f"{path.name}: top level must be an object")
    return data


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", "utf-8")
    os.replace(tmp, path)


# ----------------------------------------------------------------- project
class Project:
    def __init__(self, root) -> None:
        self.root = Path(root).resolve()
        mp = self.root / "warden.json"
        if not mp.is_file():
            raise ProjectError(f"no warden.json in {self.root} - run `warden init` first")
        self.manifest = _read_json(mp)
        self.manifest.setdefault("libraries", {})
        lp = self.root / "warden.lock"
        self.lock = _read_json(lp) if lp.is_file() else {"schema": SCHEMA, "libraries": {}}
        self.lock.setdefault("libraries", {})
        if not isinstance(self.manifest["libraries"], dict) or not isinstance(self.lock["libraries"], dict):
            raise ProjectError("malformed warden.json / warden.lock")

    def hosts(self, extra=()) -> set:
        user = self.manifest.get("allowed_hosts", [])
        if not isinstance(user, list) or not all(isinstance(h, str) for h in user):
            raise ProjectError("'allowed_hosts' must be a list of strings")
        return set(safety.DEFAULT_HOSTS) | set(user) | set(extra)

    def save(self) -> None:
        self.manifest["schema"] = SCHEMA
        self.lock["schema"] = SCHEMA
        self.manifest["libraries"] = dict(sorted(self.manifest["libraries"].items()))
        self.lock["libraries"] = dict(sorted(self.lock["libraries"].items()))
        _write_json(self.root / "warden.json", self.manifest)
        _write_json(self.root / "warden.lock", self.lock)


# Taken from vortacraftmc/core packs/merge-manifest.json (min_format = max_format = 122).
DEFAULT_PACK_FORMAT = 122


def init_project(root, namespace: str, author: str = "", game_version: str = "26.3",
                 pack_format: Optional[int] = None, description: str = "",
                 kind: str = "datapack") -> list[str]:
    root = Path(root).resolve()
    safety.validate_namespace(namespace)
    if (root / "warden.json").exists():
        raise ProjectError("warden.json already exists here")
    notes: list[str] = []

    def write_if_absent(rel: str, text: str) -> None:
        p = root / rel
        if p.exists():
            notes.append(f"kept existing {rel}")
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, "utf-8")

    if kind == "resourcepack":
        write_if_absent(f"assets/{namespace}/lang/en_us.json", "{}\n")
    else:
        for hook in ("load", "tick"):
            write_if_absent(f"data/minecraft/tags/function/{hook}.json",
                            json.dumps({"values": [f"{namespace}:global/{hook}"]}, indent=2) + "\n")
            write_if_absent(f"data/{namespace}/function/global/{hook}.mcfunction",
                            f"# {hook} entry point of {namespace}\n")
    if pack_format is None:
        pack_format = DEFAULT_PACK_FORMAT
        notes.append(f"pack format {pack_format} comes from core's merge-manifest.json - "
                     "check it matches your Minecraft version (override with --pack-format)")
    write_if_absent("pack.mcmeta", json.dumps(
        {"pack": {"description": description or namespace,
                  "min_format": pack_format, "max_format": pack_format}}, indent=2) + "\n")
    _write_json(root / "warden.json", {
        "schema": SCHEMA, "name": namespace, "version": "1.0.0", "author": author,
        "game_version": game_version, "type": kind, "libraries": {}})
    _write_json(root / "warden.lock", {"schema": SCHEMA, "libraries": {}})
    return notes


# ----------------------------------------------------------------- filesystem guards
def ensure_safe_target(root: Path, rel: str) -> Path:
    """Project-relative path whose every existing component is a real (non-symlink) entry."""
    safety.validate_rel(rel)
    cur = root
    for part in rel.split("/"):
        cur = cur / part
        if os.path.islink(cur):
            raise UnsafeInput(f"refusing to write through symlink: {rel}")
    return cur


def case_clash(root: Path, rel: str):
    """An existing path that differs from `rel` only by letter case (it would be overwritten on
    Windows/macOS although it looks like a different file on Linux), or None."""
    cur = root
    for part in rel.split("/"):
        try:
            names = os.listdir(cur)
        except OSError:
            return None
        if part not in names:
            low = part.lower()
            for n in names:
                if n.lower() == low:
                    return (cur / n).relative_to(root).as_posix()
            return None
        cur = cur / part
    return None


def _namespace_of(rel: str) -> str:
    p = rel.split("/")
    return f"{p[0]}/{p[1]}"


def _prune(root: Path, start: Path) -> None:
    stop = {root / "data", root / "assets", root}
    d = start
    while d not in stop and d.is_dir() and not any(d.iterdir()):
        d.rmdir()
        d = d.parent


def _tag_title(rel: str) -> str:
    parts = rel.split("/")
    return f"#minecraft:{'/'.join(parts[4:])[:-5]} ({parts[3]} tag)"


# ----------------------------------------------------------------- apply
def apply_content(project: Project, lib_id: str, content: LibraryContent,
                  owned: Optional[dict] = None, owned_tags: Optional[dict] = None) -> dict:
    """Validate everything first, then write; roll back fully on any failure.

    `owned_tags` is the lock's previous tag record of this library (restore case): entries it says this
    library added stay owned by it. Entries that were already present stay owned by whoever put them there."""
    owned = owned or {}
    owned_tags = owned_tags or {}
    root = project.root
    others = {rel: oid for oid, e in project.lock["libraries"].items() if oid != lib_id
              for rel in e.get("files", {})}
    conflicts: list[str] = []
    to_copy: list[tuple[str, Path]] = []
    # A library may not move into a namespace that belongs to another library or to this project.
    ns_owner = {}
    for oid, e in project.lock["libraries"].items():
        if oid != lib_id:
            for orel in e.get("files", {}):
                ns_owner.setdefault(_namespace_of(orel), oid)
    mine = project.manifest.get("name")
    for ns in content.namespaces():
        if ns in ns_owner:
            conflicts.append(f"namespace '{ns}' is already used by library '{ns_owner[ns]}'")
        elif isinstance(mine, str) and ns.split("/")[1] == mine:
            conflicts.append(f"namespace '{ns}' is this project's own namespace")
    for rel, src in sorted(content.files.items()):
        target = ensure_safe_target(root, rel)
        clash = case_clash(root, rel)
        if clash:
            conflicts.append(f"{rel} (differs only by case from existing '{clash}')")
            continue
        if rel in others:
            conflicts.append(f"{rel} (owned by library '{others[rel]}')")
        elif os.path.lexists(target):
            if target.is_file() and rel in owned and sha256_file(target) == content.hashes[rel]:
                continue                                    # already in place, untouched
            why = "modified locally" if rel in owned else "already exists"
            conflicts.append(f"{rel} ({why})")
        else:
            to_copy.append((rel, src))
    tag_plans = []
    for rel, values in sorted(content.tags.items()):
        target = ensure_safe_target(root, rel)
        clash = case_clash(root, rel)
        if clash:
            conflicts.append(f"{rel} (differs only by case from existing '{clash}')")
            continue
        if os.path.lexists(target):
            if not target.is_file():
                conflicts.append(f"{rel} (not a file)")
                continue
            original = target.read_bytes()
            doc = _read_json(target)
            if not isinstance(doc.get("values", []), list):
                raise ProjectError(f"{rel}: 'values' must be a list")
            doc.setdefault("values", [])
        else:
            original, doc = None, {"values": []}
        tag_plans.append((rel, target, original, doc, values))
    if conflicts:
        raise ConflictError("refusing to install - conflicts:\n  " + "\n  ".join(conflicts))

    created: list[Path] = []
    touched: list[tuple[Path, Optional[bytes]]] = []
    added: dict[str, list] = {}
    try:
        for rel, src in to_copy:
            t = root / rel
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, t)
            created.append(t)
        for rel, target, original, doc, values in tag_plans:
            have = {value_key(v) for v in doc["values"]}
            prev = {value_key(v) for v in (owned_tags.get(rel) or {}).get("added", [])}
            mine_added = []
            for v in values:
                k = value_key(v)
                if k not in have:
                    doc["values"].append(v)
                    have.add(k)
                    mine_added.append(v)
                elif k in prev:
                    mine_added.append(v)            # restore: still the entry this library put there
            added[rel] = mine_added
            target.parent.mkdir(parents=True, exist_ok=True)
            touched.append((target, original))
            _write_json(target, doc)
    except BaseException:
        for t in created:
            t.unlink(missing_ok=True)
            _prune(root, t.parent)
        for t, original in touched:
            if original is None:
                t.unlink(missing_ok=True)
                _prune(root, t.parent)
            else:
                t.write_bytes(original)
        raise
    return {"files": dict(sorted(content.hashes.items())),
            "tags": {rel: {"values": list(v), "added": added.get(rel, [])}
                     for rel, v in sorted(content.tags.items())},
            "integrity": content.integrity()}


def summarize(lib_id: str, source: str, commit: str, content: LibraryContent,
              report: Optional[AuditReport] = None, old_files: Optional[dict] = None) -> list[str]:
    lines = [f"Library : {lib_id}", f"Source  : {source}", f"Commit  : {commit}",
             f"Files   : {len(content.files)} in {', '.join(content.namespaces()) or '-'}"]
    if old_files is not None:
        add = sorted(set(content.hashes) - set(old_files))
        gone = sorted(set(old_files) - set(content.hashes))
        chg = sorted(r for r in set(content.hashes) & set(old_files) if content.hashes[r] != old_files[r])
        lines.append(f"Changes : +{len(add)} added, ~{len(chg)} changed, -{len(gone)} removed")
        lines += [f"  {m} {r}" for m, rs in (("+", add), ("~", chg), ("-", gone)) for r in rs[:6]]
    for rel in sorted(content.tags):
        vals = ", ".join(v if isinstance(v, str) else v["id"] for v in content.tags[rel]) or "(none)"
        lines.append(f"HOOKS   : {_tag_title(rel)} <- {vals}")
    if report is not None:
        c = report.counts()
        lines.append(f"Audit   : {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
        shown = [f for f in sorted(report.findings, key=lambda f: (-SEV[f.severity], f.path, f.line))
                 if f.installed and SEV[f.severity] >= SEV["medium"]][:8]
        lines += ["  " + format_finding(f).replace("\n", "\n  ") for f in shown]
        out_of_tree = [f for f in report.findings if not f.installed and f.severity == "high"]
        if out_of_tree:
            lines.append(f"Note    : {len(out_of_tree)} high-severity file(s) in the repo are NOT installed "
                         "(outside data/ and assets/)")
    if content.skipped:
        lines.append(f"Ignored : {', '.join(content.skipped[:8])}{' ...' if len(content.skipped) > 8 else ''}")
    return lines


# ----------------------------------------------------------------- add / install
FAIL_LEVELS = ("high", "medium", "low", "never")


def _fail_level(project: Project, override: Optional[str]) -> str:
    level = override or (project.manifest.get("audit") or {}).get("fail_on", "high")
    if level not in FAIL_LEVELS:
        raise ProjectError(f"audit.fail_on must be one of {', '.join(FAIL_LEVELS)}")
    return level


def _enforce_audit(report: AuditReport, level: str) -> None:
    hard = report.hard_blocks()
    if hard:
        raise AuditError("executable/script content inside data/ or assets/ - installation is always "
                         "refused for this:\n  " + "\n  ".join(format_finding(f).replace("\n", " ") for f in hard[:10]))
    blocking = report.blocking(level)
    if blocking:
        raise AuditError(f"audit policy (fail_on={level}) blocked this library:\n  "
                         + "\n  ".join(format_finding(f).replace("\n", "\n  ") for f in blocking[:10])
                         + ("\n  ..." if len(blocking) > 10 else "")
                         + "\nReview the source. Override per command with --fail-on medium|low|never "
                           "only if you trust it.")


def _stage_and_apply(project, lib_id, source, ref, commit, allow_local, ignore_game_version,
                     confirm: Confirm, owned=None, expected_integrity=None, owned_tags=None,
                     fail_on: Optional[str] = None, skip_audit: bool = False,
                     pre_apply: Optional[Callable[[], None]] = None, old_files: Optional[dict] = None) -> dict:
    level = _fail_level(project, fail_on)
    with tempfile.TemporaryDirectory(prefix="warden-") as tmp:
        stage = Path(tmp) / "src"
        got = fetch(source, stage, ref=ref, commit=commit, allow_local=allow_local)
        want_gv = project.manifest.get("game_version")
        lib_gv = read_meta(stage).get("game_version")
        if lib_gv and want_gv and lib_gv != want_gv and not ignore_game_version:
            raise ProjectError(f"library targets game version {lib_gv}, project uses {want_gv} "
                               "(use --ignore-game-version to override)")
        content = scan(stage)
        if expected_integrity and content.integrity() != expected_integrity:
            raise IntegrityError(f"'{lib_id}' content differs from warden.lock at the pinned commit - "
                                 "refusing to install (lock edited or source tampered)")
        report = None
        if not skip_audit:                  # restores are byte-identical to what was already approved
            report = audit_tree(stage)
            _enforce_audit(report, level)
        if confirm is not None and not confirm(summarize(lib_id, source, got, content, report, old_files)):
            raise Aborted("installation cancelled")
        if pre_apply is not None:
            pre_apply()
        record = apply_content(project, lib_id, content, owned=owned, owned_tags=owned_tags)
        if report is not None:
            record["audit"] = report.counts()
    record.update(source=source, ref=ref, commit=got)
    return record


def add_library(project: Project, source: str, ref: Optional[str] = None, name: Optional[str] = None,
                allow_local: bool = False, extra_hosts=(), ignore_game_version: bool = False,
                confirm: Confirm = None, fail_on: Optional[str] = None) -> str:
    source = safety.validate_source(source, project.hosts(extra_hosts), allow_local)
    ref = safety.validate_ref(ref) if ref else None
    lib_id = safety.validate_lib_id(name) if name else safety.name_from_source(source)
    if lib_id in project.lock["libraries"] or lib_id in project.manifest["libraries"]:
        raise ProjectError(f"'{lib_id}' is already installed (remove it first, or use --name)")
    record = _stage_and_apply(project, lib_id, source, ref, None, allow_local,
                              ignore_game_version, confirm, fail_on=fail_on)
    project.lock["libraries"][lib_id] = record
    spec = {"source": source}
    if ref:
        spec["ref"] = ref
    project.manifest["libraries"][lib_id] = spec
    project.save()
    return lib_id


def check_entry(project: Project, entry: dict) -> list[str]:
    problems = []
    for rel, sha in entry.get("files", {}).items():
        t = ensure_safe_target(project.root, rel)
        if not t.is_file():
            problems.append(f"missing  {rel}")
        elif sha256_file(t) != sha:
            problems.append(f"modified {rel}")
    for rel, rec in entry.get("tags", {}).items():
        t = ensure_safe_target(project.root, rel)
        have = set()
        if t.is_file():
            have = {value_key(v) for v in _read_json(t).get("values", [])}
        for v in rec.get("values", []):
            if value_key(v) not in have:
                problems.append(f"missing tag value {value_key(v)} in {rel}")
    return problems


def install_all(project: Project, allow_local: bool = False, extra_hosts=(),
                ignore_game_version: bool = False, confirm: Confirm = None,
                fail_on: Optional[str] = None) -> list[tuple[str, str]]:
    hosts = project.hosts(extra_hosts)
    results = []
    for lib_id, spec in sorted(project.manifest["libraries"].items()):
        safety.validate_lib_id(lib_id)
        if not isinstance(spec, dict):
            raise ProjectError(f"warden.json: malformed entry for '{lib_id}'")
        source = safety.validate_source(spec.get("source", ""), hosts, allow_local)
        ref = safety.validate_ref(spec["ref"]) if spec.get("ref") else None
        entry = project.lock["libraries"].get(lib_id)
        if entry is None and spec.get("registry"):
            _, rec = _install_from_registry(project, lib_id, spec["registry"], spec.get("spec", ""), False, False,
                                            extra_hosts, allow_local, ignore_game_version, confirm, fail_on)
            project.lock["libraries"][lib_id] = rec
            results.append((lib_id, "installed from registry (now locked)"))
            continue
        if entry is None:
            rec = _stage_and_apply(project, lib_id, source, ref, None, allow_local,
                                   ignore_game_version, confirm, fail_on=fail_on)
            project.lock["libraries"][lib_id] = rec
            results.append((lib_id, "installed (new, now locked)"))
            continue
        if entry.get("source") != source or entry.get("ref") != ref:
            raise ProjectError(f"'{lib_id}': warden.json and warden.lock disagree on source/ref - "
                               "remove and re-add the library")
        if not check_entry(project, entry):
            results.append((lib_id, "ok"))
            continue
        commit = safety.validate_commit(entry.get("commit", ""))
        rec = _stage_and_apply(project, lib_id, source, ref, commit, allow_local, True, None,
                               owned=entry.get("files", {}), expected_integrity=entry.get("integrity"),
                               owned_tags=entry.get("tags", {}), skip_audit=True)
        project.lock["libraries"][lib_id] = rec
        results.append((lib_id, f"restored from lock @ {commit[:10]}"))
    project.save()
    return results


# ----------------------------------------------------------------- remove
@dataclass
class RemoveReport:
    removed: list[str] = field(default_factory=list)
    kept_modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


def remove_library(project: Project, lib_id: str, force: bool = False) -> RemoveReport:
    entry = project.lock["libraries"].get(lib_id)
    if entry is None:
        raise ProjectError(f"'{lib_id}' is not installed")
    root, rep = project.root, RemoveReport()
    for rel, sha in entry.get("files", {}).items():
        t = ensure_safe_target(root, rel)
        if not os.path.lexists(t):
            rep.missing.append(rel)
        elif not t.is_file() or (sha256_file(t) != sha and not force):
            rep.kept_modified.append(rel)
        else:
            t.unlink()
            rep.removed.append(rel)
            _prune(root, t.parent)
    for rel, rec in entry.get("tags", {}).items():
        t = ensure_safe_target(root, rel)
        if not t.is_file():
            continue
        others_rec = [e.get("tags", {}).get(rel) for oid, e in project.lock["libraries"].items() if oid != lib_id]
        shared = {value_key(v) for r in others_rec if r for v in r.get("values", [])}
        # Lock entries written before ownership tracking have no "added": treat all values as ours (old behaviour).
        ours = rec["added"] if "added" in rec else rec.get("values", [])
        mine = {value_key(v) for v in ours} - shared
        for oid, e in project.lock["libraries"].items():          # entry still needed elsewhere: ownership moves on
            orec = e.get("tags", {}).get(rel) if oid != lib_id else None
            if orec is not None and "added" in orec:
                have = {value_key(v) for v in orec["added"]}
                for v in ours:
                    k = value_key(v)
                    if k in shared and k not in have and k in {value_key(x) for x in orec.get("values", [])}:
                        orec["added"].append(v)
                        have.add(k)
        doc = _read_json(t)
        doc["values"] = [v for v in doc.get("values", []) if value_key(v) not in mine]
        if not doc["values"] and set(doc) <= {"values"}:
            t.unlink()
            _prune(root, t.parent)
        else:
            _write_json(t, doc)
        rep.removed.append(f"{rel} (tag entries)")
    project.lock["libraries"].pop(lib_id, None)
    project.manifest["libraries"].pop(lib_id, None)
    project.save()
    return rep


def verify_all(project: Project) -> dict[str, list[str]]:
    return {lib: p for lib, e in sorted(project.lock["libraries"].items())
            if (p := check_entry(project, e))}


# ----------------------------------------------------------------- standalone audit
def audit_target(target: Optional[str], project_dir=".", ref: Optional[str] = None,
                 extra_hosts=(), allow_local: bool = False) -> tuple[str, AuditReport]:
    """Audit a project folder (default), a directory, a .zip file, or a git URL."""
    if target is None:
        return str(Path(project_dir).resolve()), audit_tree(Path(project_dir))
    if os.path.isdir(target):
        return target, audit_tree(find_pack_root(Path(target)))
    with tempfile.TemporaryDirectory(prefix="warden-audit-") as tmp:
        if os.path.isfile(target):
            if not target.lower().endswith(".zip"):
                raise ProjectError("only directories, .zip files and git URLs can be audited")
            pre = extract_zip(target, Path(tmp) / "zip")
            report = audit_tree(find_pack_root(Path(tmp) / "zip"))
            for f in pre:
                report.add(f)
            return target, report
        hosts = set(safety.DEFAULT_HOSTS) | set(extra_hosts)
        try:
            hosts |= Project(project_dir).hosts()
        except ProjectError:
            pass
        url = safety.validate_source(target, hosts, allow_local)
        if ref:
            safety.validate_ref(ref)
        stage = Path(tmp) / "src"
        commit = fetch(url, stage, ref=ref, allow_local=allow_local)
        return f"{url} @ {commit[:10]}", audit_tree(stage)


# ----------------------------------------------------------------- registries (client side)
CACHE_DIR = ".warden/cache"
_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")


def registry_add(project: Project, name: str, location: str, keys: list, threshold: int = 1) -> None:
    safety.validate_lib_id(name)
    reg.validate_location(location)
    if not keys or not all(isinstance(k, str) and _HEX64.match(k) for k in keys):
        raise ProjectError("pass at least one --key with a 64-char hex Ed25519 public key")
    if not 1 <= threshold <= len(set(keys)):
        raise ProjectError("threshold must be between 1 and the number of keys")
    project.manifest.setdefault("registries", {})[name] = {
        "url": location, "keys": sorted(set(keys)), "threshold": threshold}
    project.save()


def registry_remove(project: Project, name: str) -> None:
    if name not in project.manifest.get("registries", {}):
        raise ProjectError(f"unknown registry '{name}'")
    del project.manifest["registries"][name]
    project.lock.get("registries", {}).pop(name, None)
    project.save()


def _registry_conf(project: Project, name: str) -> dict:
    conf = project.manifest.get("registries", {}).get(name)
    if not isinstance(conf, dict):
        raise ProjectError(f"unknown registry '{name}' (add it with `warden registry add`)")
    return conf


def load_registry(project: Project, name: str, allow_stale: bool = False, offline: bool = False) -> dict:
    """Fetch (or read the cached copy of) a registry index and VERIFY it. The cache is never trusted."""
    conf = _registry_conf(project, name)
    cache = project.root / CACHE_DIR / f"{safety.validate_lib_id(name)}.index.json"
    if offline:
        if not cache.is_file():
            raise reg.RegistryError(f"no cached copy of registry '{name}'; run once online")
        raw = cache.read_bytes()
    else:
        raw = reg.fetch_bytes(conf["url"])
    last = project.lock.get("registries", {}).get(name, {}).get("version")
    signed = reg.verify_index(raw, conf["keys"], conf.get("threshold", 1), last_version=last,
                              allow_stale=allow_stale)
    if not offline:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(raw)
    project.lock.setdefault("registries", {})[name] = {"version": signed["version"]}
    return signed


def _split_spec(target: str) -> tuple[str, str]:
    lib, _, spec = target.partition("@")
    return safety.validate_lib_id(lib), spec


def _install_from_registry(project, lib_id, name, spec, allow_stale, offline, extra_hosts, allow_local,
                           ignore_game_version, confirm, fail_on, pre_apply=None, old_files=None):
    signed = load_registry(project, name, allow_stale, offline)
    entry, ver = reg.resolve(signed, lib_id, spec, project.manifest.get("game_version"), ignore_game_version)
    source = safety.validate_source(entry["source"], project.hosts(extra_hosts), allow_local)
    record = _stage_and_apply(project, lib_id, source, None, ver["commit"], allow_local, ignore_game_version,
                              confirm, expected_integrity=ver["integrity"], fail_on=fail_on,
                              pre_apply=pre_apply, old_files=old_files)
    record["registry"] = {"name": name, "version": signed["version"], "resolved": ver["version"]}
    return source, record


def add_from_registry(project: Project, target: str, registry: Optional[str] = None,
                      allow_stale: bool = False, offline: bool = False, extra_hosts=(),
                      allow_local: bool = False, ignore_game_version: bool = False,
                      confirm: Confirm = None, fail_on: Optional[str] = None) -> str:
    lib_id, spec = _split_spec(target)
    if lib_id in project.lock["libraries"] or lib_id in project.manifest["libraries"]:
        raise ProjectError(f"'{lib_id}' is already installed (remove it first)")
    names = [registry] if registry else list(project.manifest.get("registries", {}))
    if not names:
        raise ProjectError("no registry configured - `warden registry add NAME URL --key HEX`, or pass a git URL")
    last_err = None
    for name in names:
        try:
            source, record = _install_from_registry(project, lib_id, name, spec, allow_stale, offline,
                                                    extra_hosts, allow_local, ignore_game_version, confirm, fail_on)
        except reg.RegistryError as e:
            if "is not in registry" in str(e) and len(names) > 1:
                last_err = e
                continue
            raise
        project.lock["libraries"][lib_id] = record
        project.manifest["libraries"][lib_id] = {"source": source, "registry": name, "spec": spec}
        project.save()
        return lib_id
    raise last_err or reg.RegistryError(f"'{lib_id}' not found")


def search_registries(project: Project, term: str = "", registry: Optional[str] = None,
                      allow_stale: bool = False, offline: bool = False) -> list[tuple]:
    out = []
    for name in ([registry] if registry else list(project.manifest.get("registries", {}))):
        signed = load_registry(project, name, allow_stale, offline)
        for lib_id, e in sorted(signed["libraries"].items()):
            if term.lower() in lib_id or term.lower() in str(e.get("description", "")).lower():
                latest = max(e["versions"], key=lambda v: reg.semver.parse(v["version"]), default=None)
                out.append((name, lib_id, latest["version"] if latest else "-",
                            latest["game_version"] if latest else "-", e.get("description", "")))
    project.save()
    return out


def check_revocations(project: Project, refresh: bool = False) -> list[str]:
    """Flag installed libraries that a (verified) registry index has since revoked."""
    problems = []
    names = {e["registry"]["name"] for e in project.lock["libraries"].values() if "registry" in e}
    for name in sorted(names):
        try:
            signed = load_registry(project, name, allow_stale=True, offline=not refresh)
        except (reg.RegistryError, ProjectError) as e:
            problems.append(f"[{name}] could not check revocations: {e}")
            continue
        for lib_id, e in sorted(project.lock["libraries"].items()):
            r = e.get("registry")
            if r and r["name"] == name:
                why = reg.revoked_reason(signed, lib_id, r.get("resolved"), e.get("commit"))
                if why:
                    problems.append(f"{lib_id}: REVOKED by registry '{name}': {why}")
    project.save()
    return problems


# ----------------------------------------------------------------- update
def update_libraries(project: Project, names=None, force: bool = False, allow_local: bool = False,
                     extra_hosts=(), ignore_game_version: bool = False, confirm: Confirm = None,
                     fail_on: Optional[str] = None, allow_stale: bool = False,
                     offline: bool = False) -> list[tuple[str, str]]:
    """Move installed libraries to their newest allowed revision, all-or-nothing per library."""
    hosts = project.hosts(extra_hosts)
    results = []
    for lib_id in (sorted(names) if names else sorted(project.lock["libraries"])):
        entry = project.lock["libraries"].get(lib_id)
        if entry is None:
            raise ProjectError(f"'{lib_id}' is not installed")
        spec = project.manifest["libraries"].get(lib_id) or {}
        source = safety.validate_source(entry.get("source", ""), hosts, allow_local)
        edited = [p for p in check_entry(project, entry) if p.startswith("modified")]
        if edited and not force:
            results.append((lib_id, f"skipped: you edited {len(edited)} file(s) (use --force to overwrite)"))
            continue
        r = entry.get("registry")
        if r:
            signed = load_registry(project, r["name"], allow_stale, offline)
            _, ver = reg.resolve(signed, lib_id, spec.get("spec", ""), project.manifest.get("game_version"),
                                 ignore_game_version)
            newest = ver["commit"]
        else:
            with tempfile.TemporaryDirectory(prefix="warden-peek-") as tmp:
                newest = fetch(source, Path(tmp) / "p", ref=entry.get("ref"), allow_local=allow_local)
        if newest == entry["commit"]:
            results.append((lib_id, "up to date"))
            continue
        snap_lock, snap_man = copy.deepcopy(project.lock), copy.deepcopy(project.manifest)
        backups = {}
        for rel in list(entry.get("files", {})) + list(entry.get("tags", {})):
            t = ensure_safe_target(project.root, rel)
            if t.is_file():
                backups[t] = t.read_bytes()
        pre = lambda: remove_library(project, lib_id, force=True)       # noqa: E731
        try:
            if r:
                _, rec = _install_from_registry(project, lib_id, r["name"], spec.get("spec", ""), allow_stale,
                                                offline, extra_hosts, allow_local, ignore_game_version, confirm,
                                                fail_on, pre_apply=pre, old_files=entry.get("files"))
            else:
                rec = _stage_and_apply(project, lib_id, source, entry.get("ref"), None, allow_local,
                                       ignore_game_version, confirm, fail_on=fail_on, pre_apply=pre,
                                       old_files=entry.get("files"))
        except BaseException as exc:
            for t, data in backups.items():                              # put the old version back
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(data)
            project.lock.clear(); project.lock.update(snap_lock)
            project.manifest.clear(); project.manifest.update(snap_man)
            project.save()
            if isinstance(exc, (Aborted, AuditError)):
                results.append((lib_id, "not updated: " + str(exc).splitlines()[0]))
                continue
            raise
        project.lock["libraries"][lib_id] = rec
        project.manifest["libraries"][lib_id] = snap_man["libraries"][lib_id]
        project.save()
        results.append((lib_id, f"updated {entry['commit'][:10]} -> {rec['commit'][:10]}"))
    return results


# ----------------------------------------------------------------- import from sculk-cli
def import_sculk(project: Project, path, apply: bool = False, allow_local: bool = False, extra_hosts=(),
                 ignore_game_version: bool = False, confirm: Confirm = None, fail_on: Optional[str] = None,
                 allow_stale: bool = False, offline: bool = False) -> list[tuple[str, str]]:
    """Plan (default) or perform the migration of a sculk-cli libraries.json. Nothing is trusted from it:
    every source is re-validated, upgraded http->https only on allow-listed hosts, then audited as usual."""
    data = _read_json(Path(path))
    libs = data.get("libraries")
    if not isinstance(libs, list):
        raise ProjectError("not a sculk libraries.json (missing 'libraries' list)")
    hosts = project.hosts(extra_hosts)
    out = []
    if data.get("game_version") and project.manifest.get("game_version") not in (None, data["game_version"]):
        out.append(("(project)", f"note: file targets game {data['game_version']}, project uses "
                                 f"{project.manifest.get('game_version')}"))
    for item in libs:
        if not isinstance(item, dict) or not isinstance(item.get("source"), str):
            out.append(("?", "skipped: malformed entry"))
            continue
        src = item["source"]
        note = ""
        if src.startswith("http://"):
            src, note = "https://" + src[len("http://"):], " (http upgraded to https)"
        ident = item.get("identifier") if isinstance(item.get("identifier"), str) else ""
        try:
            src = safety.validate_source(src, hosts, allow_local)
            name = ident if ("://" not in ident and ident) else safety.name_from_source(src)
            safety.validate_lib_id(name)
        except UnsafeInput as e:
            out.append((ident or src[:40], f"skipped: {e}"))
            continue
        if name in project.lock["libraries"] or name in project.manifest["libraries"]:
            out.append((name, "already installed"))
            continue
        if not apply:
            out.append((name, f"would install from {src}{note}"))
            continue
        ver = item.get("version") if isinstance(item.get("version"), str) else ""
        try:
            done = False
            if project.manifest.get("registries") and ident and "://" not in ident:
                try:
                    add_from_registry(project, f"{name}@{ver}" if ver else name, None, allow_stale, offline,
                                      extra_hosts, allow_local, ignore_game_version, confirm, fail_on)
                    out.append((name, "installed from registry (pinned, signed)"))
                    done = True
                except reg.RegistryError as e:
                    if "is not in registry" not in str(e) and "no usable version" not in str(e):
                        raise
            if not done:
                add_library(project, src, None, name, allow_local, extra_hosts, ignore_game_version,
                            confirm, fail_on)
                out.append((name, f"installed from git{note}; pinned to commit {project.lock['libraries'][name]['commit'][:10]}"))
        except (Aborted, AuditError, ConflictError, ProjectError, reg.RegistryError, UnsafeInput) as e:
            out.append((name, "NOT installed: " + str(e).splitlines()[0]))
    return out
