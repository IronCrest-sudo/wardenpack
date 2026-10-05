"""Render a REAL terminal session (actual warden runs against local fixtures) into an animated GIF.

Needs Pillow (dev-only: pip install "wardenpack[showcase]"). Paths are shortened to ~/demo for display.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from . import maintain
from .core import Project, init_project, registry_add

COLS, ROWS = 112, 24
THEME = dict(bg=(13, 17, 23), fg=(201, 209, 217), prompt=(63, 185, 80), bad=(248, 81, 73), ok=(63, 185, 80),
             dim=(139, 148, 158))


def _git(cwd, *a):
    env = dict(os.environ, GIT_AUTHOR_NAME="d", GIT_AUTHOR_EMAIL="d@d", GIT_COMMITTER_NAME="d",
               GIT_COMMITTER_EMAIL="d@d", GIT_CONFIG_GLOBAL=os.devnull)
    subprocess.run(["git", *a], cwd=cwd, env=env, check=True, capture_output=True)


def _fixtures(root: Path) -> tuple[Path, list]:
    lib = root / "idsys"
    (lib / "data/idsys/function").mkdir(parents=True)
    (lib / "data/idsys/function/ids.mcfunction").write_text("scoreboard players add #next idsys 1\n")
    (lib / "warden.json").write_text('{"version":"1.0.0","game_version":"26.3"}')
    _git(lib, "init", "-q", "-b", "main"); _git(lib, "add", "-A"); _git(lib, "commit", "-q", "-m", "release")
    reg = root / "registry"
    maintain.init_registry(reg, "official")
    maintain.add_lib(reg, "idsys", str(lib), description="Unique ID generator", allow_local=True)
    key = root / "sign.key"
    pub = maintain.keygen(key)
    maintain.build(reg, key)
    proj = root / "mypack"
    proj.mkdir()
    init_project(proj, "mypack")
    registry_add(Project(proj), "official", str(reg / "index.json"), [pub])
    with zipfile.ZipFile(root / "shady.zip", "w") as z:
        z.writestr("pack/pack.mcmeta", "{}")
        z.writestr("pack/data/shady/function/tick.mcfunction", "execute as @a run op @s\n$$(cmd)\n")
        z.writestr("pack/data/shady/updater.dll", b"MZ" + b"\0" * 80)
    # (display command, real argv after `warden`, cwd)
    return proj, [("warden search", ["search", "--allow-stale"]),
                  ("warden add idsys", ["add", "idsys", "--yes", "--allow-local"]),
                  ("warden audit shady.zip", ["audit", str(root / "shady.zip")]),
                  ("warden verify", ["verify"])]


def _color(line: str):
    if "[HIGH" in line or line.startswith(("error", "aborted")):
        return THEME["bad"]
    if line.startswith(("installed", "all libraries")) or "valid" in line:
        return THEME["ok"]
    return THEME["fg"]


def record(out_gif) -> int:
    from PIL import Image, ImageDraw, ImageFont
    font = None
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "DejaVuSansMono.ttf"):
        try:
            font = ImageFont.truetype(p, 15)
            break
        except OSError:
            continue
    font = font or ImageFont.load_default()
    cw = int(font.getlength("M")) or 8
    ch = 20
    size = (COLS * cw + 24, ROWS * ch + 24)
    frames, durations = [], []

    def shot(lines, ms):
        im = Image.new("RGB", size, THEME["bg"])
        d = ImageDraw.Draw(im)
        for i, (text, col) in enumerate(lines[-ROWS:]):
            d.text((12, 12 + i * ch), text[:COLS], font=font, fill=col)
        frames.append(im)
        durations.append(ms)

    with tempfile.TemporaryDirectory(prefix="warden-demo-") as tmp:
        tmp = Path(tmp).resolve()
        proj, steps = _fixtures(tmp)
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent))
        screen = [("# Wardenpack demo - real runs on local fixtures", THEME["dim"])]
        for shown, argv, in steps:
            for n in range(0, len(shown) + 1, 3):
                shot(screen + [("$ " + shown[:n] + "_", THEME["prompt"])], 70)
            screen.append(("$ " + shown, THEME["prompt"]))
            res = subprocess.run([sys.executable, "-m", "wardenpack", "-C", str(proj), *argv],
                                 cwd=tmp, env=env, capture_output=True, text=True)
            for line in (res.stdout + res.stderr).replace(str(tmp), "~/demo").splitlines():
                screen.append((line.rstrip(), _color(line)))
            shot(screen, 2200)
        shot(screen, 3000)
    frames[0].save(out_gif, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    return len(frames)
