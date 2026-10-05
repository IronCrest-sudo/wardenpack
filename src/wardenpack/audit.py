"""Static audit of datapack content. Heuristic by nature: it finds what is *visible*, it
cannot prove a pack is safe. Nothing here executes or imports the audited content."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
MAX_FINDINGS = 500
MAX_FILE_READ = 10 * 1024 * 1024
INSTALLED_ROOTS = ("data/", "assets/")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    snippet: str = ""
    installed: bool = True        # False = lives outside data/ and assets/, Wardenpack would not install it

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditReport:
    findings: list = field(default_factory=list)
    truncated: bool = False

    def add(self, f: Finding) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            self.truncated = True
        elif f not in self.findings:
            self.findings.append(f)

    def counts(self, installed_only: bool = True) -> dict:
        out = {k: 0 for k in SEV}
        for f in self.findings:
            if f.installed or not installed_only:
                out[f.severity] += 1
        return out

    def blocking(self, fail_on: str, installed_only: bool = True) -> list:
        if fail_on == "never":
            return []
        lvl = SEV[fail_on]
        hits = [f for f in self.findings if SEV[f.severity] >= lvl and (f.installed or not installed_only)]
        return sorted(hits, key=lambda f: (-SEV[f.severity], f.path, f.line))

    def hard_blocks(self) -> list:
        return [f for f in self.findings if f.installed and f.rule.startswith("EXE-")]


# --------------------------------------------------------------------------- rule tables
_ADMIN = {
    "op": ("ADMIN-OP", "high", "grants operator status"),
    "deop": ("ADMIN-DEOP", "high", "removes operator status"),
    "stop": ("ADMIN-STOP", "high", "stops the server"),
    "ban": ("ADMIN-BAN", "high", "bans players"),
    "ban-ip": ("ADMIN-BAN", "high", "bans IP addresses"),
    "pardon": ("ADMIN-BAN", "high", "changes the ban list"),
    "pardon-ip": ("ADMIN-BAN", "high", "changes the IP ban list"),
    "whitelist": ("ADMIN-WHITELIST", "high", "changes the whitelist"),
    "save-off": ("ADMIN-SAVE", "high", "disables world saving"),
    "setidletimeout": ("ADMIN-SERVER", "high", "changes server idle timeout"),
    "publish": ("ADMIN-SERVER", "high", "opens the world to LAN/network"),
    "debug": ("ADMIN-SERVER", "high", "starts server profiling"),
    "perf": ("ADMIN-SERVER", "high", "server profiling command"),
    "jfr": ("ADMIN-SERVER", "high", "Java Flight Recorder command"),
    "transfer": ("ADMIN-TRANSFER", "high", "moves players to another server"),
    "kick": ("ADMIN-KICK", "medium", "kicks players"),
    "reload": ("RELOAD", "medium", "reloads datapacks from inside a function"),
    "datapack": ("DATAPACK-CTL", "medium", "enables/disables datapacks"),
    "forceload": ("FORCELOAD", "medium", "force-loads chunks (lag, memory)"),
    "gamerule": ("GAMERULE", "medium", "changes world rules"),
    "save-all": ("ADMIN-SAVE", "low", "forces a world save"),
    "save-on": ("ADMIN-SAVE", "low", "changes autosave"),
    "defaultgamemode": ("WORLD-SETTING", "low", "changes default game mode"),
    "difficulty": ("WORLD-SETTING", "low", "changes difficulty"),
    "setworldspawn": ("WORLD-SETTING", "low", "moves world spawn"),
    "worldborder": ("WORLD-SETTING", "low", "changes the world border"),
}

_ALLOWED_EXT = {".json", ".mcfunction", ".nbt", ".snbt", ".png", ".ogg", ".mcmeta", ".txt", ".md",
                ".fsh", ".vsh", ".glsl", ".properties", ".lang", ".ttf", ".otf", ".bin", ".mcassetsroot"}
_EXE_EXT = {".exe", ".dll", ".so", ".dylib", ".jar", ".class", ".msi", ".scr", ".com", ".pif",
            ".cpl", ".apk", ".app", ".lnk", ".hta"}
_SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".psm1", ".sh", ".bash", ".py", ".pyc", ".js", ".mjs", ".vbs",
               ".vbe", ".jse", ".wsf", ".reg", ".rb", ".pl", ".php"}
_TEXT_EXT = {".mcfunction", ".json", ".txt", ".md", ".mcmeta", ".snbt", ".properties", ".lang"}
_CLICK_CMD = re.compile(r'(?:"value"|"command"|\bcommand)\s*:\s*"(/?[^"]*)"')
_FUNC_ID = re.compile(r"^#?[a-z0-9_.-]+:[a-z0-9_./-]+$")


# --------------------------------------------------------------------------- command parsing
def commands_in(raw: str) -> list:
    """All commands that may run from this line: [(word, args, is_macro_line, full_text)].

    `execute ... run X` and `return run X` are unwrapped at *every* ' run ' so a dangerous
    command cannot hide behind a string that happens to contain ' run '.
    """
    text = raw.strip()
    if not text or text.startswith("#"):
        return []
    macro = text.startswith("$")
    if macro:
        text = text[1:].lstrip()
    text = text.lstrip("/")
    first = text.split(" ", 1)[0]
    cands = [text]
    if first in ("execute", "return"):
        parts = text.split(" run ")
        cands = [" run ".join(parts[i:]).lstrip().lstrip("/") for i in range(1, len(parts))] or [text]
    out = []
    for c in cands:
        word, _, args = c.partition(" ")
        out.append((word, args.strip(), macro, c))
    return out


def _volume(args: str):
    t = args.split()[:6]
    if len(t) < 6:
        return None
    try:
        if all(x.startswith("~") for x in t):
            v = [float(x[1:] or 0) for x in t]
        elif not any(x[:1] in "~^" for x in t):
            v = [float(x) for x in t]
        else:
            return None
    except ValueError:
        return None
    return (abs(v[3] - v[0]) + 1) * (abs(v[4] - v[1]) + 1) * (abs(v[5] - v[2]) + 1)


def _check_command(report, path, lineno, word, args, macro, full, installed, prefix="", raw=""):
    snippet = (raw or full)[:120]

    def emit(rule, sev, msg):
        report.add(Finding(prefix + rule, sev, path, lineno, msg, snippet, installed))

    if macro and "$(" in word:
        emit("MACRO-CMD", "high", "command name is built from a macro variable (arbitrary command injection)")
        return
    w = word.lower()
    if w in _ADMIN:
        emit(*_ADMIN[w])
    elif w == "kill" and re.search(r"@a\b|@e(?!\[[^\]]*type=)", args):
        emit("KILL-MASS", "medium", "kills every player/entity matched by a broad selector")
    elif w == "clear" and (not args or re.match(r"@[ae]\b", args)):
        emit("CLEAR-MASS", "medium", "clears inventories of many players")
    elif w == "scoreboard" and re.match(r"(players\s+reset\s+\*|objectives\s+remove)", args):
        emit("SCORE-WIPE", "medium", "wipes scoreboard data")
    elif w == "data" and re.match(r"(merge|modify)\s+storage\s+minecraft:", args):
        emit("DATA-VANILLA-STORAGE", "high", "writes to a vanilla storage namespace (can corrupt world data)")
    elif w == "data" and re.match(r"merge\s+entity\s+@a\b", args):
        emit("DATA-MERGE-BROAD", "medium", "data merge aimed at all players")
    elif w in ("fill", "clone"):
        vol = _volume(args)
        if vol and vol >= 10000:
            emit("BLOCK-VOLUME", "medium", f"edits a very large region (~{int(vol)} blocks)")


# --------------------------------------------------------------------------- per-file analysis
def _analyze_mcfunction(report, rel, data: bytes, installed, edges):
    if b"\x00" in data[:4096]:
        report.add(Finding("BINARY-IN-TEXT", "medium", rel, 0, "NUL bytes in a .mcfunction file", "", installed))
        return
    fid = _function_id(rel)
    for n, raw in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if len(raw) > 3000:
            report.add(Finding("LONG-LINE", "low", rel, n, f"unusually long line ({len(raw)} chars)", raw[:80], installed))
        if raw.count("\\u") >= 40:
            report.add(Finding("OBFUSCATION", "low", rel, n, "many \\u escapes (possible obfuscation)", raw[:80], installed))
        conditional = bool(re.search(r"\b(if|unless)\b", raw))
        for word, args, macro, full in commands_in(raw):
            _check_command(report, rel, n, word, args, macro, full, installed, raw=raw.strip())
            if word == "function" and fid:
                target = args.split(" ", 1)[0]
                if _FUNC_ID.match(target) and not target.startswith("#"):
                    edges.append((fid, target, conditional, rel, n))
        if "run_command" in raw:
            cmds = _CLICK_CMD.findall(raw)
            report.add(Finding("CLICK-RUN", "medium", rel, n,
                               "text component runs a command as the clicking player", raw.strip()[:120], installed))
            for c in cmds:
                for word, args, macro, full in commands_in(c):
                    _check_command(report, rel, n, word, args, macro, full, installed, prefix="CLICK-", raw=c)


def _function_id(rel: str):
    p = rel.split("/")
    if len(p) >= 4 and p[0] == "data" and p[2] in ("function", "functions") and rel.endswith(".mcfunction"):
        return f"{p[1]}:{'/'.join(p[3:])[:-len('.mcfunction')]}"
    return None


def _analyze_json(report, rel, data: bytes, installed):
    p = rel.split("/")
    if len(p) < 3 or p[0] != "data":
        return
    try:
        doc = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    if p[1] == "minecraft" and p[2] == "tags" and len(p) >= 5 and p[3] in ("function", "functions"):
        vals = [v if isinstance(v, str) else str(v.get("id")) for v in doc.get("values", [])
                if isinstance(v, (str, dict))]
        name = p[4][:-5] if p[4].endswith(".json") else p[4]
        if name == "tick" and vals:
            report.add(Finding("HOOK-TICK", "low", rel, 0, "runs every tick: " + ", ".join(vals), "", installed))
            if len(vals) > 20:
                report.add(Finding("MANY-TICK", "low", rel, 0,
                                   f"{len(vals)} functions run every tick (20x/sec)", "", installed))
        elif name == "load" and vals:
            report.add(Finding("HOOK-LOAD", "info", rel, 0, "runs on load/reload: " + ", ".join(vals), "", installed))
    if p[2] in ("advancement", "advancements"):
        func = (doc.get("rewards") or {}).get("function") if isinstance(doc.get("rewards"), dict) else None
        crit = doc.get("criteria") if isinstance(doc.get("criteria"), dict) else {}
        ticks = any(isinstance(c, dict) and c.get("trigger") == "minecraft:tick" for c in crit.values())
        if func and ticks:
            report.add(Finding("ADV-TICK", "medium", rel, 0,
                               f"advancement with tick trigger runs {func} for players repeatedly", "", installed))
        elif func:
            report.add(Finding("ADV-FUNC", "info", rel, 0, f"advancement reward runs {func}", "", installed))


def _check_file_type(report, rel, full: Path, installed):
    ext = os.path.splitext(rel)[1].lower()
    try:
        with open(full, "rb") as f:
            head = f.read(1024)
    except OSError:
        return
    exe_magic = None
    if head[:2] == b"MZ" and len(head) >= 0x40:
        off = int.from_bytes(head[0x3C:0x40], "little")
        if head[off:off + 4] == b"PE\0\0" or 1024 < off < 0x100000:
            exe_magic = "Windows executable (PE)"
    elif head[:4] == b"\x7fELF":
        exe_magic = "Linux executable (ELF)"
    elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        exe_magic = "native/Java binary (Mach-O or class)"
    elif head[:2] == b"#!" and ext not in _TEXT_EXT:
        exe_magic = "script with shebang"
    if ext in _EXE_EXT:
        report.add(Finding("EXE-EXT", "high", rel, 0, f"executable file type '{ext}'", "", installed))
    elif ext in _SCRIPT_EXT:
        report.add(Finding("EXE-EXT" if installed else "SCRIPT-FILE", "high" if installed else "low",
                           rel, 0, f"script file type '{ext}'" + ("" if installed else " (outside data/assets, not installed)"),
                           "", installed))
    if exe_magic:
        report.add(Finding("EXE-MAGIC", "high", rel, 0,
                           f"content is a {exe_magic}" + (f", disguised as '{ext}'" if ext not in _EXE_EXT | _SCRIPT_EXT else ""),
                           "", installed))
    if head[:4] == b"PK\x03\x04" and ext not in _EXE_EXT:
        report.add(Finding("NESTED-ARCHIVE", "medium", rel, 0, "archive inside the pack", "", installed))
    if installed and ext not in _ALLOWED_EXT | _EXE_EXT | _SCRIPT_EXT and ext != ".zip":
        report.add(Finding("UNKNOWN-TYPE", "low", rel, 0, f"unusual file type '{ext or '(none)'}'", "", installed))


def _find_cycles(report, edges):
    graph = {}
    where = {}
    for src, dst, cond, rel, n in edges:
        if not cond:
            graph.setdefault(src, set()).add(dst)
            where.setdefault((src, dst), (rel, n))
    seen, stack, reported = set(), [], set()

    def dfs(node):
        seen.add(node)
        stack.append(node)
        for nxt in sorted(graph.get(node, ())):
            if nxt in stack:
                cyc = stack[stack.index(nxt):]
                key = frozenset(cyc)
                if key not in reported:
                    reported.add(key)
                    rel, n = where[(node, nxt)]
                    report.add(Finding("RECURSION", "medium", rel, n,
                                       "unconditional function cycle: " + " -> ".join(cyc + [nxt]), "", True))
            elif nxt not in seen:
                dfs(nxt)
        stack.pop()

    for node in sorted(graph):
        if node not in seen:
            dfs(node)


# --------------------------------------------------------------------------- entry points
def audit_tree(root) -> AuditReport:
    root = Path(root)
    report, edges = AuditReport(), []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(dirnames + filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            installed = rel.startswith(INSTALLED_ROOTS)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                report.add(Finding("SYMLINK", "high", rel, 0, "symbolic link", "", installed))
                continue
            if not stat.S_ISREG(st.st_mode):
                if not stat.S_ISDIR(st.st_mode):
                    report.add(Finding("SPECIAL-FILE", "high", rel, 0, "not a regular file", "", installed))
                continue
            _check_file_type(report, rel, full, installed)
            if st.st_size > MAX_FILE_READ:
                report.add(Finding("BIG-FILE", "low", rel, 0, "file too large to analyse", "", installed))
                continue
            ext = os.path.splitext(rel)[1].lower()
            if ext not in (".mcfunction", ".json"):
                continue
            data = full.read_bytes()
            if ext == ".mcfunction":
                _analyze_mcfunction(report, rel, data, installed, edges)
            else:
                _analyze_json(report, rel, data, installed)
    _find_cycles(report, edges)
    return report


def format_finding(f: Finding) -> str:
    loc = f"{f.path}:{f.line}" if f.line else f.path
    tail = "" if f.installed else "  (not installed)"
    s = f"[{f.severity.upper():6}] {f.rule:<16} {loc}  {f.message}{tail}"
    return s + (f"\n           > {f.snippet}" if f.snippet else "")
