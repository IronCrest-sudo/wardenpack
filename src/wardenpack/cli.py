from __future__ import annotations

import argparse
import json
import re
import sys

from . import __version__
from .audit import SEV, format_finding
from . import maintain
from .core import (FAIL_LEVELS, Project, add_from_registry, add_library, audit_target, check_revocations,
                   init_project, install_all, registry_add, registry_remove, remove_library,
                   search_registries, verify_all)
from .safety import DEFAULT_HOSTS
from .errors import Aborted, WardenError


def _confirm_factory(assume_yes: bool):
    def confirm(lines: list) -> bool:
        print("\n".join(lines))
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            print("\nnon-interactive session: pass --yes to approve this installation", file=sys.stderr)
            return False
        return input("\nInstall this library? [y/N] ").strip().lower() in ("y", "yes")
    return confirm


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden", description="Security-first datapack library manager")
    p.add_argument("-C", "--project-dir", default=".", help="project directory (default: .)")
    p.add_argument("--version", action="version", version=f"wardenpack {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create warden.json and the datapack skeleton")
    s.add_argument("namespace")
    s.add_argument("--author", default="")
    s.add_argument("--game-version", default="26.3")
    s.add_argument("--pack-format", type=int, default=None)

    def net(sp):
        sp.add_argument("--allow-host", action="append", default=[], metavar="HOST")
        sp.add_argument("--allow-local", action="store_true", help=argparse.SUPPRESS)
        sp.add_argument("--ignore-game-version", action="store_true")
        sp.add_argument("-y", "--yes", action="store_true", help="approve without prompting")
        sp.add_argument("--fail-on", choices=FAIL_LEVELS, default=None,
                        help="block libraries with findings at/above this severity (default: high, "
                             "or audit.fail_on in warden.json)")

    s = sub.add_parser("add", help="install a library: registry id[@version-spec] or a git URL")
    s.add_argument("source", metavar="ID_OR_URL")
    s.add_argument("--ref", help="branch or tag (git URLs only)")
    s.add_argument("--name", help="library id (git URLs only; default: repository name)")
    s.add_argument("--registry", help="only look in this registry")
    s.add_argument("--offline", action="store_true", help="use the cached registry index")
    s.add_argument("--allow-stale", action="store_true", help="accept an expired (but correctly signed) index")
    net(s)

    s = sub.add_parser("install", help="install everything in warden.json, exactly as locked")
    net(s)

    s = sub.add_parser("remove", help="uninstall a library (only files it owns and you did not edit)")
    s.add_argument("name")
    s.add_argument("--force", action="store_true", help="also delete files you modified")

    s = sub.add_parser("audit", help="statically audit a folder, .zip or git URL (default: this project)")
    s.add_argument("target", nargs="?", help="directory, .zip file or https/ssh git URL")
    s.add_argument("--ref")
    s.add_argument("--allow-host", action="append", default=[], metavar="HOST")
    s.add_argument("--allow-local", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--fail-on", choices=FAIL_LEVELS, default="high",
                   help="exit with status 2 if findings at/above this severity exist (default: high)")
    s.add_argument("-v", "--verbose", action="store_true", help="also print info-level findings")

    sub.add_parser("list", help="show installed libraries")
    s = sub.add_parser("verify", help="check installed files against warden.lock (and registry revocations)")
    s.add_argument("--refresh", action="store_true", help="re-download registry indexes to check revocations")

    s = sub.add_parser("search", help="search configured registries")
    s.add_argument("term", nargs="?", default="")
    s.add_argument("--registry")
    s.add_argument("--offline", action="store_true")
    s.add_argument("--allow-stale", action="store_true")

    r = sub.add_parser("registry", help="manage trusted registries").add_subparsers(dest="rcmd", required=True)
    s = r.add_parser("add", help="trust a registry (pin its public key)")
    s.add_argument("name")
    s.add_argument("url", help="https:// URL or absolute path of index.json")
    s.add_argument("--key", action="append", default=[], required=True, metavar="HEX",
                   help="Ed25519 public key (64 hex chars); repeatable")
    s.add_argument("--threshold", type=int, default=1, help="signatures required (default 1)")
    r.add_parser("list", help="show trusted registries")
    s = r.add_parser("remove")
    s.add_argument("name")

    m = sub.add_parser("maintain", help="registry maintainer tools").add_subparsers(dest="mcmd", required=True)
    s = m.add_parser("keygen", help="create an Ed25519 signing key (needs `cryptography`)")
    s.add_argument("path")
    s = m.add_parser("init", help="scaffold a registry repository")
    s.add_argument("directory")
    s.add_argument("--name", required=True)
    s = m.add_parser("add-lib", help="pin, scan and audit a library version into the registry")
    s.add_argument("directory")
    s.add_argument("id")
    s.add_argument("source")
    s.add_argument("--ref")
    s.add_argument("--version")
    s.add_argument("--game-version")
    s.add_argument("--description", default="")
    s.add_argument("--license", default="")
    s.add_argument("--fail-on", choices=FAIL_LEVELS, default="high")
    s.add_argument("--allow-host", action="append", default=[])
    s.add_argument("--allow-local", action="store_true", help=argparse.SUPPRESS)
    s = m.add_parser("build", help="build and sign index.json")
    s.add_argument("directory")
    s.add_argument("--key", required=True, help="path to the private key file")
    s.add_argument("--valid-days", type=int, default=180)
    s = m.add_parser("check", help="re-verify every pinned commit still matches its recorded hash")
    s.add_argument("directory")
    s.add_argument("--allow-host", action="append", default=[])
    s.add_argument("--allow-local", action="store_true", help=argparse.SUPPRESS)
    s = m.add_parser("site", help="render a signed index.json into a static website")
    s.add_argument("index")
    s.add_argument("--out", required=True)
    s.add_argument("--key", action="append", required=True, metavar="HEX")
    s.add_argument("--base-url", default="https://example.org")
    s.add_argument("--assets", help="folder with showcase *.gif files to include")
    s = m.add_parser("showcase", help="record a demo GIF from real warden runs (needs Pillow)")
    s.add_argument("--out", default="showcase.gif")
    s = m.add_parser("verify", help="verify a signed index.json against a public key")
    s.add_argument("file")
    s.add_argument("--key", action="append", required=True, metavar="HEX")
    return p


def run(args) -> int:
    if args.cmd == "init":
        for n in init_project(args.project_dir, args.namespace, args.author,
                              args.game_version, args.pack_format):
            print("note:", n)
        print(f"initialised '{args.namespace}'")
        return 0
    if args.cmd == "audit":
        return run_audit(args)
    if args.cmd == "maintain":
        return run_maintain(args)
    project = Project(args.project_dir)
    if args.cmd == "add":
        if _ID_SPEC.match(args.source):
            if args.ref or args.name:
                print("error: --ref/--name only apply to git URLs", file=sys.stderr)
                return 1
            lib = add_from_registry(project, args.source, args.registry, args.allow_stale, args.offline,
                                    args.allow_host, args.allow_local, args.ignore_game_version,
                                    _confirm_factory(args.yes), args.fail_on)
        else:
            lib = add_library(project, args.source, ref=args.ref, name=args.name,
                              allow_local=args.allow_local, extra_hosts=args.allow_host,
                              ignore_game_version=args.ignore_game_version,
                              confirm=_confirm_factory(args.yes), fail_on=args.fail_on)
        print(f"\ninstalled '{lib}' @ {project.lock['libraries'][lib]['commit'][:10]}")
    elif args.cmd == "install":
        for lib, status in install_all(project, args.allow_local, args.allow_host,
                                       args.ignore_game_version, _confirm_factory(args.yes),
                                       args.fail_on):
            print(f"{lib}: {status}")
    elif args.cmd == "remove":
        rep = remove_library(project, args.name, args.force)
        print(f"removed {len(rep.removed)} item(s)")
        for rel in rep.kept_modified:
            print(f"kept (modified or not a file): {rel}")
        for rel in rep.missing:
            print(f"already gone: {rel}")
    elif args.cmd == "list":
        for lib, e in sorted(project.lock["libraries"].items()):
            print(f"{lib}  {e['commit'][:10]}  {len(e['files'])} files  {e['source']}")
        if not project.lock["libraries"]:
            print("(no libraries)")
    elif args.cmd == "verify":
        bad = verify_all(project)
        for lib, problems in bad.items():
            print(f"{lib}:")
            for pr in problems:
                print("  ", pr)
        rev = check_revocations(project, args.refresh)
        for line in rev:
            print(line)
        if not bad and not rev:
            print("all libraries match warden.lock; no revocations found")
        return 2 if (bad or any("REVOKED" in r for r in rev)) else 0
    elif args.cmd == "search":
        rows = search_registries(project, args.term, args.registry, args.allow_stale, args.offline)
        for name, lib, ver, gv, desc in rows:
            print(f"{lib:<24} {ver:<10} mc {gv:<8} [{name}]  {desc}")
        if not rows:
            print("(nothing found)")
    elif args.cmd == "registry":
        if args.rcmd == "add":
            registry_add(project, args.name, args.url, args.key, args.threshold)
            print(f"trusting registry '{args.name}' with {len(set(args.key))} pinned key(s)")
        elif args.rcmd == "remove":
            registry_remove(project, args.name)
        else:
            for n, c in sorted(project.manifest.get("registries", {}).items()):
                print(f"{n}  {c['url']}  keys={len(c['keys'])} threshold={c.get('threshold', 1)}")
    return 0


_ID_SPEC = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}(@[^\s/:]*)?$")


def run_maintain(args) -> int:
    c = args.mcmd
    if c == "keygen":
        try:
            pub = maintain.keygen(args.path)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"private key written to {args.path} (keep it OFFLINE, never commit it)")
        print(f"public key: {pub}")
    elif c == "init":
        maintain.init_registry(args.directory, args.name)
        print(f"registry '{args.name}' scaffolded in {args.directory}")
    elif c == "add-lib":
        e = maintain.add_lib(args.directory, args.id, args.source, args.ref, args.version, args.game_version,
                             args.description, args.license, args.fail_on,
                             set(DEFAULT_HOSTS) | set(args.allow_host), args.allow_local)
        v = e["versions"][-1]
        print(f"{args.id} {v['version']} pinned @ {v['commit'][:10]}  audit={v['audit']}")
    elif c == "build":
        sg = maintain.build(args.directory, args.key, args.valid_days)
        print(f"signed index v{sg['version']}: {len(sg['libraries'])} librar(ies), expires {sg['expires']}")
    elif c == "check":
        bad = maintain.check(args.directory, set(DEFAULT_HOSTS) | set(args.allow_host), args.allow_local)
        for b in bad:
            print("PROBLEM:", b)
        print("all pinned versions verified" if not bad else "")
        return 2 if bad else 0
    elif c == "site":
        from .site import build_site
        n = build_site(args.index, args.out, args.key, args.base_url, args.assets)
        print(f"wrote {n} page(s) to {args.out}")
    elif c == "showcase":
        try:
            from .showcase import record
            print(f"wrote {args.out} ({record(args.out)} frames)")
        except ImportError:
            print('error: showcase needs Pillow: pip install "wardenpack[showcase]"', file=sys.stderr)
            return 1
    elif c == "verify":
        from . import registry as reg
        sg = reg.verify_index(open(args.file, "rb").read(), args.key, allow_stale=True)
        print(f"valid signature: '{sg['name']}' v{sg['version']}, expires {sg['expires']}")
    return 0


def run_audit(args) -> int:
    name, report = audit_target(args.target, args.project_dir, args.ref, args.allow_host, args.allow_local)
    counts = report.counts(installed_only=False)
    blocking = report.blocking(args.fail_on, installed_only=False)
    if args.format == "json":
        print(json.dumps({"target": name, "summary": counts, "truncated": report.truncated,
                          "blocking": len(blocking),
                          "findings": [f.as_dict() for f in report.findings]}, indent=2))
    else:
        print(f"Audit of {name}")
        print(f"  {counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} info")
        shown = sorted(report.findings, key=lambda f: (-SEV[f.severity], f.path, f.line))
        for f in shown:
            if args.verbose or f.severity != "info":
                print(format_finding(f))
        if report.truncated:
            print("(output truncated at 500 findings)")
        print("\nHeuristic scan: no findings does NOT prove a pack is safe; it only means these rules did not match.")
    return 2 if blocking else 0


def main(argv=None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except Aborted as e:
        print(f"aborted: {e}", file=sys.stderr)
        return 1
    except WardenError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
