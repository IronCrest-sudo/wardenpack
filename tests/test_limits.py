"""Regression tests for the former 'Known limits': tag ownership, namespace isolation,
case-insensitive filesystems, macro-built targets."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_audit import tree
from test_wardenpack import Base, make_lib
from wardenpack.audit import audit_tree
from wardenpack.core import Project, install_all, remove_library
from wardenpack.errors import ConflictError

TICK = "data/minecraft/tags/function/tick.json"


def tick_values(proj: Path):
    return json.loads((proj / TICK).read_text())["values"]


class TestTagOwnership(Base):
    def lib(self, name, ns, entry=None):
        return make_lib(self.tmp, name, {f"data/{ns}/function/a.mcfunction": "say a\n",
                                         TICK: {"values": [entry or f"{ns}:tick"]}})

    def test_preexisting_identical_entry_survives_remove(self):
        (self.proj / TICK).write_text(json.dumps({"values": ["mypack:global/tick", "idsys:tick"]}))
        self.add(self.lib("idsys", "idsys"))
        rec = json.loads((self.proj / "warden.lock").read_text())["libraries"]["idsys"]["tags"][TICK]
        self.assertEqual(rec["added"], [])
        remove_library(Project(self.proj), "idsys")
        self.assertEqual(tick_values(self.proj), ["mypack:global/tick", "idsys:tick"])

    def test_own_entry_is_still_removed(self):
        self.add(self.lib("idsys", "idsys"))
        self.assertIn("idsys:tick", tick_values(self.proj))
        remove_library(Project(self.proj), "idsys")
        self.assertEqual(tick_values(self.proj), ["mypack:global/tick"])

    def test_restore_keeps_ownership(self):
        self.add(self.lib("idsys", "idsys"))
        (self.proj / "data/idsys/function/a.mcfunction").unlink()          # force a restore from the lock
        install_all(Project(self.proj), allow_local=True)
        self.assertTrue((self.proj / "data/idsys/function/a.mcfunction").exists())
        remove_library(Project(self.proj), "idsys")
        self.assertEqual(tick_values(self.proj), ["mypack:global/tick"])

    def test_shared_entry_ownership_moves_to_remaining_library(self):
        self.add(self.lib("one", "one", "shared:tick"))
        self.add(self.lib("two", "two", "shared:tick"))
        remove_library(Project(self.proj), "one")
        self.assertIn("shared:tick", tick_values(self.proj))              # two still needs it
        remove_library(Project(self.proj), "two")
        self.assertEqual(tick_values(self.proj), ["mypack:global/tick"])  # and nothing is orphaned

    def test_legacy_lock_without_added_keeps_old_behaviour(self):
        self.add(self.lib("idsys", "idsys"))
        lp = self.proj / "warden.lock"
        lock = json.loads(lp.read_text())
        del lock["libraries"]["idsys"]["tags"][TICK]["added"]
        lp.write_text(json.dumps(lock))
        remove_library(Project(self.proj), "idsys")
        self.assertEqual(tick_values(self.proj), ["mypack:global/tick"])


class TestNamespaceIsolation(Base):
    def test_cannot_enter_another_librarys_namespace(self):
        self.add(make_lib(self.tmp, "alpha", {"data/alpha/function/a.mcfunction": "say a"}))
        sneaky = make_lib(self.tmp, "sneaky", {"data/alpha/function/other.mcfunction": "say b"})
        with self.assertRaises(ConflictError) as cm:
            self.add(sneaky)
        self.assertIn("already used by library 'alpha'", str(cm.exception))
        self.assertFalse((self.proj / "data/alpha/function/other.mcfunction").exists())

    def test_cannot_enter_project_namespace(self):
        evil = make_lib(self.tmp, "evil", {"data/mypack/function/x.mcfunction": "say x"})
        with self.assertRaises(ConflictError) as cm:
            self.add(evil)
        self.assertIn("project's own namespace", str(cm.exception))

    def test_distinct_namespaces_still_install(self):
        self.add(make_lib(self.tmp, "alpha", {"data/alpha/function/a.mcfunction": "say a"}))
        self.add(make_lib(self.tmp, "beta", {"data/beta/function/a.mcfunction": "say b"}))


class TestCaseInsensitiveFs(Base):
    def test_existing_file_differing_by_case_blocks_install(self):
        d = self.proj / "data/idsys/function"
        d.mkdir(parents=True)
        (d / "A.mcfunction").write_text("say mine")
        lib = make_lib(self.tmp, "idsys", {"data/idsys/function/a.mcfunction": "say lib"})
        with self.assertRaises(ConflictError) as cm:
            self.add(lib)
        self.assertIn("only by case", str(cm.exception))
        self.assertEqual((d / "A.mcfunction").read_text(), "say mine")

    def test_directory_differing_by_case_blocks_install(self):
        (self.proj / "data/IdSys/function").mkdir(parents=True)
        lib = make_lib(self.tmp, "idsys", {"data/idsys/function/a.mcfunction": "say lib"})
        with self.assertRaises(ConflictError):
            self.add(lib)


class TestMacroTargets(unittest.TestCase):
    def rules(self, text, tmp):
        return {f.rule for f in audit_tree(tree(tmp, {"data/x/function/a.mcfunction": text})).findings}

    def test_macro_function_target_and_click_macro(self):
        import tempfile
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b, \
                tempfile.TemporaryDirectory() as c, tempfile.TemporaryDirectory() as d:
            self.assertIn("MACRO-FUNCTION", self.rules("$function foo:$(name)", Path(a)))
            self.assertIn("MACRO-FUNCTION", self.rules("$function $(ns):main", Path(b)))
            self.assertNotIn("MACRO-FUNCTION", self.rules("function foo:bar", Path(c)))
            line = '$tellraw @a {"click_event":{"action":"run_command","command":"$(c)"}}'
            self.assertIn("CLICK-MACRO-CMD", self.rules(line, Path(d)))


if __name__ == "__main__":
    unittest.main()
