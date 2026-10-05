"""Static website generator: renders a SIGNED registry index into plain HTML (no framework, no CDN).

The index is verified against the pinned key(s) first, every value is HTML-escaped, and the
pages ship a strict Content-Security-Policy (self-hosted CSS + one tiny search script).
"""
from __future__ import annotations

import html
import shutil
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from . import ed25519, registry as reg, semver

CSS = """:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--card:#f6f8fa;--bd:#d0d7de;--ac:#1a7f37;--bad:#cf222e}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ac:#3fb950;--bad:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px}a{color:var(--ac)}code,pre{font-family:ui-monospace,monospace;background:var(--card);border:1px solid var(--bd);border-radius:6px}
code{padding:1px 5px}pre{padding:12px;overflow-x:auto}.mut{color:var(--mut)}.bad{color:var(--bad)}
input{width:100%;padding:10px;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:6px;font:inherit}
ul.libs{list-style:none;padding:0}ul.libs li{border:1px solid var(--bd);background:var(--card);border-radius:8px;padding:12px;margin:10px 0}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}td,th{border-bottom:1px solid var(--bd);padding:6px 10px;text-align:left}
.banner{border:1px solid var(--bad);border-radius:8px;padding:10px;margin:12px 0}img{max-width:100%;border:1px solid var(--bd);border-radius:8px}"""

JS = """const q=document.getElementById('q');if(q){q.addEventListener('input',()=>{const t=q.value.toLowerCase();
document.querySelectorAll('ul.libs li').forEach(li=>{li.hidden=!li.dataset.t.includes(t)})})}"""

PAGE = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'; "
        "script-src 'self'; img-src 'self'\"><title>{title}</title>"
        "<link rel=\"stylesheet\" href=\"{root}style.css\"></head><body><main>{body}</main>{script}</body></html>")


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _page(title, body, root="", script=False):
    return PAGE.format(title=_e(title), body=body, root=root,
                       script=f'<script src="{root}search.js"></script>' if script else "")


def _audit(a) -> str:
    if not isinstance(a, dict):
        return "-"
    return f"{a.get('high', 0)} high / {a.get('medium', 0)} med / {a.get('low', 0)} low"


def build_site(index_path, out_dir, keys: list, base_url: str = "https://example.org",
               assets_dir: Optional[str] = None, today: Optional[date] = None) -> int:
    raw = Path(index_path).read_bytes()
    today = today or datetime.now(timezone.utc).date()
    signed = reg.verify_index(raw, keys, allow_stale=True, today=today)       # refuses unsigned/tampered
    expired = date.fromisoformat(signed["expires"]) < today
    out = Path(out_dir)
    (out / "libraries").mkdir(parents=True, exist_ok=True)
    (out / "registry").mkdir(exist_ok=True)
    (out / "style.css").write_text(CSS)
    (out / "search.js").write_text(JS)
    (out / "registry" / "index.json").write_bytes(raw)                       # exactly what clients verify
    shots = []
    if assets_dir and Path(assets_dir).is_dir():
        (out / "showcase").mkdir(exist_ok=True)
        for g in sorted(Path(assets_dir).glob("*.gif")):
            shutil.copyfile(g, out / "showcase" / g.name)
            shots.append(g.name)
    base = base_url.rstrip("/")
    revoked = {(r.get("id"), r.get("version")) for r in signed.get("revocations", [])}
    banner = (f'<div class="banner bad">This index expired on {_e(signed["expires"])}. '
              'It is still correctly signed, but may miss newer releases or revocations.</div>') if expired else ""
    fps = "".join(f"<li><code>{_e(ed25519.keyid(bytes.fromhex(k)))}</code> <code>{_e(k)}</code></li>" for k in keys)
    items = []
    for lib_id, e in sorted(signed["libraries"].items()):
        top = max(e["versions"], key=lambda v: semver.parse(v["version"]), default=None)
        text = f"{lib_id} {e.get('description', '')}".lower()
        items.append(f'<li data-t="{_e(text)}"><a href="libraries/{_e(lib_id)}.html"><b>{_e(lib_id)}</b></a> '
                     f'<span class="mut">{_e(top["version"] if top else "-")} · Minecraft {_e(top["game_version"] if top else "-")}'
                     f'</span><br>{_e(e.get("description", ""))}</li>')
        rows = "".join(
            f"<tr><td>{_e(v['version'])}{' <span class=bad>REVOKED</span>' if (lib_id, v['version']) in revoked else ''}</td>"
            f"<td>{_e(v['game_version'])}</td><td><code>{_e(v['commit'][:10])}</code></td><td>{_e(_audit(v.get('audit')))}</td></tr>"
            for v in sorted(e["versions"], key=lambda v: semver.parse(v["version"]), reverse=True))
        src = e["source"]
        link = f'<a href="{_e(src)}" rel="noopener">{_e(src)}</a>' if src.startswith("https://") else _e(src)
        body = (f'<p><a href="../index.html">&larr; all libraries</a></p><h1>{_e(lib_id)}</h1>{banner}'
                f'<p>{_e(e.get("description", ""))}</p><p class="mut">License: {_e(e.get("license", "unknown"))} · Source: {link}</p>'
                f'<pre>warden add {_e(lib_id)}</pre><table><tr><th>Version</th><th>Minecraft</th><th>Commit</th>'
                f'<th>Audit (heuristic)</th></tr>{rows}</table>'
                '<p class="mut">Every install is pinned to the commit and content hash shown in the signed index, '
                'and is audited again on your machine. Audit counts are heuristic: they never prove safety.</p>')
        (out / "libraries" / f"{lib_id}.html").write_text(_page(lib_id, body, "../"))
    gallery = "".join(f'<p><img src="showcase/{_e(n)}" alt="demo recording {_e(n)}"></p>' for n in shots)
    home = (f'<h1>{_e(signed["name"])}</h1><p class="mut">Wardenpack registry · index v{_e(signed["version"])} · '
            f'signed {_e(signed["created"])} · expires {_e(signed["expires"])}</p>{banner}'
            '<h2>Use it</h2><p>Pin this registry\'s public key yourself - never trust a key you only saw on a website '
            'you have not verified:</p>'
            f'<pre>warden registry add {_e(signed["name"])} {_e(base)}/registry/index.json --key &lt;KEY&gt;\n'
            'warden search\nwarden add &lt;library&gt;</pre>'
            f'<p>Signing key(s):</p><ul>{fps}</ul>{gallery}<h2>Libraries ({len(items)})</h2>'
            f'<input id="q" placeholder="Search libraries" aria-label="Search libraries"><ul class="libs">{"".join(items)}</ul>')
    (out / "index.html").write_text(_page(signed["name"], home, "", script=True))
    return len(items) + 1
