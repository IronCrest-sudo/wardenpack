import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wardenpack import safety
from wardenpack.core import (Project, add_library, init_project, install_all, remove_library,
                             verify_all)
from wardenpack.errors import (ConflictError, IntegrityError, ScanError, UnsafeInput)

GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_GLOBAL=os.devnull)


def git(cwd, *a):
    subprocess.run(["git", *a], cwd=cwd, env=GIT_ENV, check=True, capture_output=True)


def make_lib(base: Path, name: str, files: dict) -> str:
    repo = base / name
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text))
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return str(repo)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.proj = self.tmp / "proj"
        self.proj.mkdir()
        init_project(self.proj, "mypack", pack_format=1)
        self.p = Project(self.proj)
        self.kw = dict(allow_local=True, confirm=lambda lines: True)

    def tearDown(self):
        self._t.cleanup()

    def add(self, url, **extra):
        self.p = Project(self.proj)
        return add_library(self.p, url, **{**self.kw, **extra})


class TestSafety(unittest.TestCase):
    H = safety.DEFAULT_HOSTS

    def test_accepts_https(self):
        self.assertTrue(safety.validate_source("https://github.com/o/r", self.H))
        self.assertTrue(safety.validate_source("ssh://git@codeberg.org/o/r.git", self.H))

    def test_rejects_dangerous(self):
        for bad in ["ext::sh -c id", "--upload-pack=x", "-oProxyCommand=x", "http://github.com/o/r",
                    "file:///etc", "https://evil.com/o/r", "https://u:p@github.com/o/r",
                    "https://github.com:8443/o/r", "https://github.com/o", "https://github.com/o/../r",
                    "https://github.com/o/r?x=1", "https://github.com/o/r\n", "git@github.com:o/r",
                    "/abs/local/path", ""]:
            with self.assertRaises(UnsafeInput, msg=bad):
                safety.validate_source(bad, self.H)

    def test_ref_and_paths(self):
        for bad in ["-x", "a..b", "a@{1}", "x.lock", "", "a b"]:
            with self.assertRaises(UnsafeInput, msg=bad):
                safety.validate_ref(bad)
        for bad in ["../x", "/etc/passwd", "a//b", "a/../b", "C:/x", "a\\b", ".", ""]:
            with self.assertRaises(UnsafeInput, msg=bad):
                safety.validate_rel(bad)
        self.assertEqual(safety.validate_rel("data/ns/function/a.mcfunction"), "data/ns/function/a.mcfunction")

    def test_lib_ids(self):
        for bad in ["../x", "A", "-x", "a/b", ""]:
            with self.assertRaises(UnsafeInput):
                safety.validate_lib_id(bad)


class TestInstall(Base):
    def lib(self, name="idsys", extra=None):
        files = {"data/idsys/function/a.mcfunction": "say a\n",
                 "data/minecraft/tags/function/tick.json": {"values": ["idsys:tick"]},
                 "README.md": "ignored", "pack.mcmeta": "{}"}
        files.update(extra or {})
        return make_lib(self.tmp, name, files)

    def test_add_remove_roundtrip(self):
        url = self.lib()
        lib = self.add(url)
        self.assertEqual(lib, "idsys")
        self.assertTrue((self.proj / "data/idsys/function/a.mcfunction").is_file())
        self.assertFalse((self.proj / "README.md").exists())
        tick = json.loads((self.proj / "data/minecraft/tags/function/tick.json").read_text())
        self.assertEqual(tick["values"], ["mypack:global/tick", "idsys:tick"])
        lock = json.loads((self.proj / "warden.lock").read_text())
        self.assertEqual(len(lock["libraries"]["idsys"]["commit"]), 40)
        self.assertEqual(verify_all(Project(self.proj)), {})
        rep = remove_library(Project(self.proj), "idsys")
        self.assertFalse((self.proj / "data/idsys").exists())
        tick = json.loads((self.proj / "data/minecraft/tags/function/tick.json").read_text())
        self.assertEqual(tick["values"], ["mypack:global/tick"])
        self.assertEqual(json.loads((self.proj / "warden.lock").read_text())["libraries"], {})

    def test_modified_file_is_kept_on_remove(self):
        self.add(self.lib())
        f = self.proj / "data/idsys/function/a.mcfunction"
        f.write_text("say mine\n")
        self.assertIn("modified", " ".join(verify_all(Project(self.proj))["idsys"]))
        rep = remove_library(Project(self.proj), "idsys")
        self.assertTrue(f.exists())
        self.assertEqual(rep.kept_modified, ["data/idsys/function/a.mcfunction"])

    def test_conflict_leaves_no_partial_state(self):
        self.add(self.lib())
        other = make_lib(self.tmp, "other", {"data/zzz/function/z.mcfunction": "say z",
                                              "data/idsys/function/a.mcfunction": "say clash"})
        before = sorted(str(p) for p in self.proj.rglob("*"))
        with self.assertRaises(ConflictError):
            self.add(other)
        self.assertEqual(before, sorted(str(p) for p in self.proj.rglob("*")))

    def test_vanilla_override_rejected(self):
        url = make_lib(self.tmp, "bad", {"data/minecraft/loot_table/x.json": "{}"})
        with self.assertRaises(ScanError):
            self.add(url)
        self.assertFalse((self.proj / "data/minecraft/loot_table").exists())

    def test_tag_replace_rejected(self):
        url = make_lib(self.tmp, "bad2", {"data/a/function/x.mcfunction": "",
                                           "data/minecraft/tags/function/load.json":
                                           {"replace": True, "values": ["a:x"]}})
        with self.assertRaises(ScanError):
            self.add(url)

    def test_symlink_rejected(self):
        repo = self.tmp / "sym"
        (repo / "data/a/function").mkdir(parents=True)
        (repo / "data/a/function/x.mcfunction").write_text("say")
        try:
            os.symlink("/etc/passwd", repo / "data/a/function/leak.mcfunction")
        except OSError:
            self.skipTest("symlinks unsupported")
        git(repo, "init", "-q", "-b", "main"); git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "x")
        with self.assertRaises(ScanError):
            self.add(str(repo))

    def test_unapproved_install_changes_nothing(self):
        url = self.lib()
        self.p = Project(self.proj)
        with self.assertRaises(Exception):
            add_library(self.p, url, allow_local=True, confirm=lambda lines: False)
        self.assertFalse((self.proj / "data/idsys").exists())

    def test_shared_tag_value_survives_other_removal(self):
        self.add(self.lib("a", {"data/a/function/f.mcfunction": "x"}))  # id 'a'
        b = make_lib(self.tmp, "b", {"data/b/function/f.mcfunction": "x",
                                      "data/minecraft/tags/function/tick.json": {"values": ["idsys:tick"]}})
        self.add(b)
        remove_library(Project(self.proj), "a")
        tick = json.loads((self.proj / "data/minecraft/tags/function/tick.json").read_text())
        self.assertIn("idsys:tick", tick["values"])

    def test_install_restores_from_lock(self):
        self.add(self.lib())
        import shutil
        shutil.rmtree(self.proj / "data/idsys")
        res = install_all(Project(self.proj), allow_local=True)
        self.assertTrue(res[0][1].startswith("restored"))
        self.assertTrue((self.proj / "data/idsys/function/a.mcfunction").is_file())

    def test_tampered_lock_integrity_blocks_install(self):
        self.add(self.lib())
        import shutil
        shutil.rmtree(self.proj / "data/idsys")
        lock = json.loads((self.proj / "warden.lock").read_text())
        lock["libraries"]["idsys"]["integrity"] = "0" * 64
        (self.proj / "warden.lock").write_text(json.dumps(lock))
        with self.assertRaises(IntegrityError):
            install_all(Project(self.proj), allow_local=True)
        self.assertFalse((self.proj / "data/idsys").exists())

    def test_malicious_lock_source_is_validated(self):
        self.add(self.lib())
        man = json.loads((self.proj / "warden.json").read_text())
        man["libraries"]["idsys"]["source"] = "ext::sh -c touch /tmp/pwned"
        (self.proj / "warden.json").write_text(json.dumps(man))
        with self.assertRaises(UnsafeInput):
            install_all(Project(self.proj), allow_local=True)

    def test_path_traversal_in_lock_is_rejected(self):
        self.add(self.lib())
        lock = json.loads((self.proj / "warden.lock").read_text())
        lock["libraries"]["idsys"]["files"]["../../outside.txt"] = "0" * 64
        (self.proj / "warden.lock").write_text(json.dumps(lock))
        with self.assertRaises(UnsafeInput):
            remove_library(Project(self.proj), "idsys")


if __name__ == "__main__":
    unittest.main()
