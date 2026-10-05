import json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wardenpack import Base as GitBase, git, make_lib
from test_registry import Base as RegBase
from wardenpack.core import Project, import_sculk, init_project, update_libraries


def commit(repo, files, msg="update"):
    repo = Path(repo)
    for rel, text in files.items():
        p = repo / rel
        if text is None:
            p.unlink()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


class TestUpdate(GitBase):
    def setUp(self):
        super().setUp()
        self.url = make_lib(self.tmp, "lib", {"data/lib/function/a.mcfunction": "say 1\n",
                                              "data/lib/function/old.mcfunction": "say old\n"})
        self.add(self.url)

    def upd(self, **kw):
        return update_libraries(Project(self.proj), allow_local=True, confirm=kw.pop("confirm", lambda l: True), **kw)

    def test_up_to_date(self):
        self.assertEqual(self.upd(), [("lib", "up to date")])

    def test_update_applies_diff(self):
        commit(self.url, {"data/lib/function/a.mcfunction": "say 2\n", "data/lib/function/old.mcfunction": None,
                          "data/lib/function/new.mcfunction": "say new\n"})
        seen = []
        res = self.upd(confirm=lambda l: seen.extend(l) or True)
        self.assertTrue(res[0][1].startswith("updated"))
        d = self.proj / "data/lib/function"
        self.assertEqual((d / "a.mcfunction").read_text(), "say 2\n")
        self.assertFalse((d / "old.mcfunction").exists())
        self.assertTrue((d / "new.mcfunction").exists())
        self.assertTrue(any(l.startswith("Changes") and "+1 added" in l and "-1 removed" in l for l in seen))
        self.assertEqual(json.loads((self.proj / "warden.lock").read_text())["libraries"]["lib"]["commit"],
                         Project(self.proj).lock["libraries"]["lib"]["commit"])
        self.assertEqual(self.upd(), [("lib", "up to date")])

    def test_local_edits_block_unless_force(self):
        commit(self.url, {"data/lib/function/a.mcfunction": "say 2\n"})
        f = self.proj / "data/lib/function/a.mcfunction"
        f.write_text("say mine\n")
        self.assertTrue(self.upd()[0][1].startswith("skipped"))
        self.assertEqual(f.read_text(), "say mine\n")
        self.assertTrue(self.upd(force=True)[0][1].startswith("updated"))

    def test_declined_or_blocked_update_restores_everything(self):
        before = {p: p.read_bytes() for p in self.proj.rglob("*") if p.is_file()}
        lock_before = (self.proj / "warden.lock").read_text()
        commit(self.url, {"data/lib/function/a.mcfunction": "say 2\n", "data/lib/function/z.mcfunction": "op @s\n"})
        res = self.upd()                                           # audit blocks (high finding)
        self.assertTrue(res[0][1].startswith("not updated"))
        res = self.upd(fail_on="never", confirm=lambda l: False)    # user declines
        self.assertTrue(res[0][1].startswith("not updated"))
        self.assertEqual(before, {p: p.read_bytes() for p in self.proj.rglob("*") if p.is_file()})
        self.assertEqual(lock_before, (self.proj / "warden.lock").read_text())


class TestRegistryUpdate(RegBase):
    def test_registry_update_picks_newer_version(self):
        self.publish(version="1.0.0")
        self.build()
        self.add("idsys")
        self.publish(version="1.1.0")
        self.build()
        res = update_libraries(Project(self.proj), allow_local=True, confirm=lambda l: True)
        self.assertTrue(res[0][1].startswith("updated"), res)
        lock = json.loads((self.proj / "warden.lock").read_text())
        self.assertEqual(lock["libraries"]["idsys"]["registry"]["resolved"], "1.1.0")
        self.assertEqual(lock["registries"]["official"]["version"], 2)


class TestImportSculk(GitBase):
    def write(self, libs, gv="26.3"):
        p = self.tmp / "libraries.json"
        p.write_text(json.dumps({"author": "x", "version": "1.0.0", "game_version": gv, "libraries": libs}))
        return p

    def test_dry_run_normalises_and_rejects(self):
        p = self.write([
            {"identifier": "id-system", "source": "http://github.com/officialbarden/id-system", "version": "1.0.0"},
            {"identifier": "evil", "source": "http://evil.example/o/r"},
            {"identifier": "x", "source": "ext::sh -c id"},
            "garbage"])
        res = dict(import_sculk(Project(self.proj), p))
        self.assertIn("would install from https://github.com/officialbarden/id-system", res["id-system"])
        self.assertIn("http upgraded", res["id-system"])
        self.assertTrue(res["evil"].startswith("skipped"))
        self.assertTrue(res["x"].startswith("skipped"))
        self.assertTrue(res["?"].startswith("skipped"))
        self.assertEqual(Project(self.proj).lock["libraries"], {})        # dry run changed nothing

    def test_apply_installs_pinned_and_continues_after_a_blocked_one(self):
        good = make_lib(self.tmp, "good", {"data/good/function/a.mcfunction": "say hi\n"})
        bad = make_lib(self.tmp, "bad", {"data/bad/function/a.mcfunction": "op @s\n"})
        p = self.write([{"identifier": "bad", "source": bad, "version": "1.0.0"},
                        {"identifier": "good", "source": good, "version": "1.0.0"}])
        res = dict(import_sculk(Project(self.proj), p, apply=True, allow_local=True, confirm=lambda l: True))
        self.assertTrue(res["bad"].startswith("NOT installed"))
        self.assertIn("pinned to commit", res["good"])
        lock = Project(self.proj).lock["libraries"]
        self.assertEqual(set(lock), {"good"})
        self.assertEqual(len(lock["good"]["commit"]), 40)

    def test_not_a_sculk_file(self):
        p = self.tmp / "x.json"
        p.write_text("{}")
        from wardenpack.errors import ProjectError
        with self.assertRaises(ProjectError):
            import_sculk(Project(self.proj), p)


class TestInitRp(unittest.TestCase):
    def test_resourcepack_skeleton(self):
        with tempfile.TemporaryDirectory() as t:
            init_project(t, "mypack", kind="resourcepack")
            self.assertTrue((Path(t) / "assets/mypack/lang/en_us.json").is_file())
            self.assertFalse((Path(t) / "data").exists())
            self.assertEqual(json.loads((Path(t) / "warden.json").read_text())["type"], "resourcepack")


if __name__ == "__main__":
    unittest.main()
