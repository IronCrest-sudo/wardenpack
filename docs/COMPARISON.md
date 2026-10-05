# Wardenpack vs. sculk-cli

Sources: sculk-cli's public README (GPL-3.0, Go, 55 commits, 5 stars when read) and Wardenpack's own code and tests.
**Not verified:** sculk-cli's source code (GitHub blocked automated access to `src/` and `cmd/`), its `website/`
and `server/` folders, and any claim about third-party datapacks. Wardenpack shares ideas, not code, with sculk-cli.

| Topic | sculk-cli (per README) | Wardenpack |
|---|---|---|
| Language / license | Go, GPL-3.0, single binary | Python 3.10+, stdlib only, Unlicense; needs Python |
| Project types | datapack and resource pack (`init --dp/--rp`) | both (`init`, `init --rp`) |
| Manifest | `libraries.json` (id, source, version, game_version) | `warden.json` + `warden.lock` (commit + SHA-256 of every file) |
| Library by id | internal hashmap, approval via Discord | signed registry; you pin the Ed25519 key yourself |
| Library by URL | yes (README example uses `http://`) | `https://`/`ssh://` only, host allow-list, no ports/credentials |
| Reproducible install | `sculk install` from `libraries.json` (no hashes documented) | `warden install` restores the pinned commit and refuses changed content |
| Version selection | `id@1.0.0/26.2`, `@/26.2`, comparisons are TODO | `id@1.2.3`, `^`, `~`, `>=1.2,<2`; game version enforced |
| Update / uninstall | listed as done | `update` (change list, all-or-nothing, rollback); `remove` deletes only unedited files it owns |
| Conflicts | "conflict-less merging" | refuses and rolls back; vanilla `minecraft` tags merged with per-library ownership |
| Hooks / advancements | README: may be installed "without a warning" with `--ignore` | summary of `#minecraft:tick/load` hooks, static audit, confirmation |
| Security audit | none documented | `warden audit` on folders, zips (safe extraction) and git URLs; CI exit code |
| Revocation / rollback / expiry | none documented | signed revocations, rollback protection, index expiry |
| Templates (`template --create/--delete/--add`) | yes | **not implemented** (semantics undocumented) |
| `config doMerge false` (separate pack) | TODO | **not implemented**; libraries keep their own namespaces |
| Website | TODO box unchecked (repo has `website/`, unseen) | static generator from the signed index, strict CSP |
| Showcase GIFs | TODO | recorded from real runs (`maintain showcase`) |
| Migration | - | `warden import-sculk libraries.json` (dry run by default) |

## Advantages of Wardenpack
Supply-chain integrity (pinned commits and hashes, signed index, revocation), safer defaults (strict URLs, symlink and
path checks, audit before install, atomic rollback), no third-party dependencies for clients, easy to extend in Python.

## Disadvantages / honest limits
- **No ecosystem yet:** zero libraries are registered; sculk-cli has a community and a Discord review process.
- Needs Python (no single binary built; `zipapp`/PyInstaller not attempted).
- The audit is heuristic; it cannot prove a pack safe, and it can false-positive on legitimate admin-style packs.
- Signing needs a human with the offline key; a dormant maintainer means an expired index (existing locks keep working).
- Younger code: 70 tests, but no real-world use, no real network registry fetch exercised in testing.
- Missing sculk features: `template`, `config doMerge`.
