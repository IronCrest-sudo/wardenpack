# Wardenpack

A security-first library manager for Minecraft datapacks (command: `warden`).
Python 3.10+, **no third-party dependencies**, Unlicense.

Wardenpack is an independent, clean-room design: it shares the *idea* of a datapack
package manager with other tools but copies no code from them.

## Commands

```
warden init <namespace> [--pack-format N] [--game-version 26.3] [--author NAME]
warden add <https-or-ssh-url> [--ref BRANCH_OR_TAG] [--name ID] [--yes]
warden install            # restores exactly what warden.lock pins
warden remove <name>      # deletes only files it owns and you did not edit
warden verify             # re-hash installed files against warden.lock
warden update [names...] [--force]   # newest allowed revision, change list, rollback on failure
warden import-sculk [libraries.json] [--apply]   # migrate from sculk-cli (dry run by default)
warden list
warden audit [folder | pack.zip | https-url] [--format text|json|sarif] [--fail-on high|medium|low|never]
```

`add` and fresh `install` run the audit automatically on the staged copy. Default policy:
**block on any high finding** (`--fail-on`, or `"audit": {"fail_on": "medium"}` in `warden.json`).
Executables/scripts inside `data/` or `assets/` are **always** refused, whatever the policy.
`warden audit` exits with status 2 when findings reach the threshold, so it works in CI.
`--format sarif` emits SARIF 2.1.0 for GitHub code scanning:

```yaml
- run: warden audit . --format sarif --fail-on never > warden.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: warden.sarif }
```

See [docs/COMPARISON.md](docs/COMPARISON.md) for an honest feature/limit comparison with sculk-cli.

## Registry (Phase 3): signed, pinned, low-maintenance

```
warden registry add official https://example.org/index.json --key <64-hex-public-key>
warden search [term]          warden add idsys            warden add "idsys@^1.2"
warden verify --refresh       # also checks registry revocations
```

How trust works:
- You pin the registry's **Ed25519 public key** yourself (`--key`). The key is never taken from the
  index, the network, or the package. `--threshold N` requires N distinct trusted signatures.
- `index.json` is signed over canonical JSON (formatting is irrelevant). Each version records the
  **commit** and the **content integrity hash**; Wardenpack refuses anything that differs.
- A registry **cannot widen your host allow-list**: its `source` URLs go through the same checks as
  `warden add <url>`. Every registry install is still scanned and audited locally.
- **Rollback protection:** the highest index version seen is stored in `warden.lock`; older indexes are rejected.
- **Expiry:** an expired index is refused for *new* resolutions (`--allow-stale` overrides). Installs
  already pinned in `warden.lock` never need the registry, so a dormant registry cannot break them.
- **Revocations** are part of the signed index; `warden verify` flags installed revoked commits/versions,
  and revoked versions are skipped when resolving.
- Verification uses `cryptography` when installed, otherwise a pure-Python RFC 8032 implementation
  (tested against the RFC vector and cross-checked with `cryptography`). Signing needs `pip install "wardenpack[sign]"`.
- Add `.warden/` (the verified-index cache) to your `.gitignore`.

Maintainer workflow (offline key, PR-reviewed libraries):

```
warden maintain keygen sign.key                 # keep OFFLINE; prints the public key
warden maintain init registry-repo --name official
warden maintain add-lib registry-repo idsys https://github.com/o/idsys --version 1.0.0 --game-version 26.3
warden maintain check registry-repo             # CI: pinned commits still hash identically
warden maintain build registry-repo --key sign.key --valid-days 180
```

Published versions are immutable (same version + different commit is rejected). Choose `--valid-days`
as a trade-off: long validity suits an inactive maintainer, but lengthens the window in which a
frozen index can hide newer releases or revocations.

## What is different (and why)

| Risk in naive "clone and merge" managers | Wardenpack |
|---|---|
| Arbitrary URL reaches `git` (`ext::`, `-option`, `http://`) | https/ssh only, host allow-list, no credentials/ports, `--` separator, `GIT_ALLOW_PROTOCOL`, hooks disabled, no prompts |
| Moving branch/tag changes what you get later | `warden.lock` pins the **commit** and a per-file **SHA-256**; `install` refuses content that differs |
| Path traversal / symlinks inside a library | Every path validated; symlinks, special files, oversized trees are rejected before anything is written |
| Library silently hooks `#minecraft:tick`/`load` | Staged, **summarised and confirmed** (`HOOKS:` lines) before install |
| Library overrides vanilla files | Only `data/minecraft/tags/**.json` is merged (no `replace: true`); everything else under `minecraft` is rejected |
| Uninstall deletes your edits | Ownership + hash manifest; edited files are kept |
| Half-installed state after an error | Validate everything first, write, roll back on any failure |

## Audit rules (Phase 2)

| Rule | Severity | What it catches |
|---|---|---|
| `ADMIN-*`, `CLICK-ADMIN-*` | high | `op`, `deop`, `stop`, `ban*`, `pardon*`, `whitelist`, `save-off`, `transfer`, `publish`, `debug`... also when hidden behind `execute ... run`, `return run`, or inside a clickable chat component |
| `MACRO-CMD` | high | a macro line whose command name is a `$(variable)` (arbitrary command injection) |
| `EXE-EXT`, `EXE-MAGIC` | high (always blocks install) | `.exe .dll .jar .sh .py ...` inside `data/`/`assets/`, or file *contents* that are PE/ELF/Mach-O/class binaries disguised as `.png`/`.txt`/... |
| `SYMLINK`, `SPECIAL-FILE`, `ZIP-TRAVERSAL`, `ZIP-SYMLINK` | high | links, device files, zip entries that would escape the folder |
| `KILL-MASS`, `CLEAR-MASS`, `SCORE-WIPE`, `BLOCK-VOLUME`, `RELOAD`, `DATAPACK-CTL`, `FORCELOAD`, `GAMERULE`, `ADMIN-KICK` | medium | broad destructive or world-wide commands |
| `CLICK-RUN`, `ADV-TICK`, `RECURSION`, `NESTED-ARCHIVE` | medium | chat links that run commands, advancements firing every tick, unconditional function cycles, archives inside the pack |
| `CMDBLOCK-INJECT`, `CMDBLOCK-NBT`, `CMDBLOCK-<rule>` | medium (inner command keeps its own severity) | a command that plants a command block/minecart (`setblock`, `summon`, `data merge` with `Command:`), or a `.nbt`/`.snbt` structure that carries one; the planted command is audited too |
| `CLICK-RUN` (JSON) | medium | `run_command` click events and dialog actions in **any** JSON file (dialogs, books, loot tables, item components), not just `.mcfunction` |
| `MACRO-FUNCTION` | medium | `$function` whose target contains `$(variable)` |
| `TICK-CTL` | medium | `tick rate/freeze/step/sprint` |
| `WIN-NAME`, `CASE-COLLISION` | medium | Windows device names (`con`, `nul`...), trailing dot/space, `:` streams; paths that differ only by case. Both are *refused* at install time |
| `NBT-BOMB`, `JSON-DEEP`, `NBT-CORRUPT` | medium/low | gzip bombs in structures, absurdly nested JSON, undecodable NBT |
| `HOOK-TICK`, `UNKNOWN-TYPE`, `LONG-LINE`, `OBFUSCATION`, `SCRIPT-FILE` | low | runs every tick, odd file types, minified/escaped lines, scripts outside `data/` (not installed) |
| `HOOK-LOAD`, `ADV-FUNC` | info | where the library attaches |

Zips are extracted by Wardenpack's own extractor (no traversal, symlinks, or zip bombs), never by the OS.

## Known limits

- The audit is **heuristic**. It matches known-dangerous patterns; it does not prove a pack is safe and cannot
  see behaviour that only emerges at runtime. Treat "no findings" as "these rules did not match", and read what
  you install.
- Command detection is syntactic. Macros are handled where the danger is visible in the text (a command name or
  `function` target built from `$(variable)`, including inside click events), but selectors, storage contents and
  macro *arguments* are not evaluated, so a harmful command assembled from runtime data cannot be seen.
- Libraries keep their own `data/<ns>/` namespace; Wardenpack does **not** rewrite it. A library that enters a
  namespace owned by another library or by your project is refused, so collisions fail loudly at install time.
  Renaming is deliberately not offered: rewriting `old:` ids inside functions, macros, storage, scoreboards and NBT
  strings cannot be done soundly, and rewritten files would no longer match the upstream hashes you pinned.
- Direct `warden add <url>` trusts whatever the allow-listed host serves at the commit you approve; the signed
  registry (above) is the way to get an independent key to vouch for it.
- Tag ownership is recorded in `warden.lock` (`added`). Removing a library only removes tag entries *it* added;
  entries that were already there stay. If you add an identical entry by hand *after* installing, it cannot be told
  apart from the library's own and is removed with it. Lock files from before 0.7.0 have no record and keep the old
  behaviour until the library is re-added or updated.

## Changelog

**0.7.0** - Tag entries are removed only if the library added them (ownership moves to the remaining library when
two share one); libraries cannot enter another library's or the project's namespace; installs refuse files that
differ only by letter case from existing ones (Windows/macOS overwrite); `MACRO-FUNCTION` rule and macro variables
inside click commands are checked. Lock files gain `added` per tag file (older locks still load).

**0.6.0** - `/minecraft:op`-style namespaced commands no longer evade rules; command-block/minecart planting and
NBT structures are audited; click/dialog actions in all JSON; Windows-name and case-collision hardening;
SARIF output; **fixed**: absurdly nested JSON crashed `audit`, tag scanning, `verify_index` and project loading with
an uncaught `RecursionError` (now reported/rejected cleanly).

## Develop

```
python -m unittest discover -s tests -v
```
