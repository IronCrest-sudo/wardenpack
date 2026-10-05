import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_wardenpack import Base, make_lib
from wardenpack.archive import extract_zip
from wardenpack.audit import audit_tree, commands_in
from wardenpack.core import Project, add_library, audit_target
from wardenpack.errors import AuditError, ScanError


def tree(base: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return base


class TestRules(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def rules(self, files):
        r = audit_tree(tree(self.root, files))
        return {f.rule for f in r.findings}

    def mc(self, text, name="a"):
        return self.rules({f"data/x/function/{name}.mcfunction": text})

    def test_command_unwrapping_cannot_hide(self):
        self.assertIn("ADMIN-OP", self.mc("execute as @a run op @s"))
        self.assertIn("ADMIN-OP", self.mc("execute as @a at @s run return run op @s"))
        self.assertIn("ADMIN-OP", self.mc("execute if entity @s[name=\"a run b\"] run op @s"))
        self.assertIn("ADMIN-STOP", self.mc("/stop"))
        self.assertIn("ADMIN-TRANSFER", self.mc("transfer example.com 25565"))

    def test_macro_command_injection(self):
        self.assertIn("MACRO-CMD", self.mc("$$(cmd)"))
        self.assertIn("MACRO-CMD", self.mc("$execute as @a run $(cmd)"))
        self.assertNotIn("MACRO-CMD", self.mc("$say hello $(name)"))

    def test_benign_function_is_clean(self):
        r = self.rules({"data/x/function/a.mcfunction": "say hi\nscoreboard players add @s t 1\n# op @s\n"})
        self.assertEqual(r, set())

    def test_mass_commands_and_volume(self):
        self.assertIn("KILL-MASS", self.mc("kill @e"))
        self.assertNotIn("KILL-MASS", self.mc("kill @e[type=zombie]"))
        self.assertNotIn("KILL-MASS", self.mc("kill @s"))
        self.assertIn("CLEAR-MASS", self.mc("clear @a"))
        self.assertIn("SCORE-WIPE", self.mc("scoreboard players reset * obj"))
        self.assertIn("BLOCK-VOLUME", self.mc("fill ~ ~ ~ ~100 ~100 ~100 stone"))
        self.assertNotIn("BLOCK-VOLUME", self.mc("fill ~ ~ ~ ~3 ~3 ~3 stone"))

    def test_click_events(self):
        r = self.mc('tellraw @a {"text":"x","clickEvent":{"action":"run_command","value":"/op Steve"}}')
        self.assertIn("CLICK-RUN", r)
        self.assertIn("CLICK-ADMIN-OP", r)
        r = self.mc('tellraw @a {text:"x",click_event:{action:"run_command",command:"/stop"}}')
        self.assertIn("CLICK-ADMIN-STOP", r)

    def test_recursion(self):
        self.assertIn("RECURSION", self.rules({"data/x/function/a.mcfunction": "function x:a\n"}))
        self.assertIn("RECURSION", self.rules({"data/x/function/a.mcfunction": "function x:b\n",
                                               "data/x/function/b.mcfunction": "function x:a\n"}))
        self.assertNotIn("RECURSION", self.rules({
            "data/x/function/a.mcfunction": "execute if score @s t matches 1.. run function x:a\n"}))
        self.assertNotIn("RECURSION", self.rules({
            "data/x/function/a.mcfunction": "schedule function x:a 1t\n"}))

    def test_executables_and_masquerade(self):
        r = self.rules({"data/x/function/a.mcfunction": "say hi", "data/x/evil.exe": b"MZ" + b"\0" * 100})
        self.assertIn("EXE-EXT", r)
        pe = bytearray(b"MZ" + b"\0" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\0\0" + b"\0" * 64)
        self.assertIn("EXE-MAGIC", self.rules({"data/x/note.txt": bytes(pe)}))
        self.assertIn("EXE-MAGIC", self.rules({"assets/x/a.png": b"\x7fELF" + b"\0" * 60}))
        self.assertIn("EXE-EXT", self.rules({"data/x/run.sh": "echo hi"}))
        self.assertIn("NESTED-ARCHIVE", self.rules({"assets/x/a.png": b"PK\x03\x04" + b"\0" * 30}))

    def test_script_outside_data_is_not_installed(self):
        r = audit_tree(tree(self.root, {"data/x/function/a.mcfunction": "say hi", "build.py": "print(1)"}))
        f = [x for x in r.findings if x.rule == "SCRIPT-FILE"][0]
        self.assertFalse(f.installed)
        self.assertEqual(r.hard_blocks(), [])

    def test_hooks_and_advancement(self):
        files = {"data/minecraft/tags/function/tick.json": json.dumps({"values": ["x:t"]}),
                 "data/x/advancement/a.json": json.dumps({"criteria": {"c": {"trigger": "minecraft:tick"}},
                                                          "rewards": {"function": "x:r"}})}
        r = self.rules(files)
        self.assertTrue({"HOOK-TICK", "ADV-TICK"} <= r)

    def test_symlink_reported(self):
        tree(self.root, {"data/x/function/a.mcfunction": "say"})
        try:
            os.symlink("/etc/passwd", self.root / "data/x/function/l.mcfunction")
        except OSError:
            self.skipTest("no symlinks")
        self.assertIn("SYMLINK", {f.rule for f in audit_tree(self.root).findings})

    def test_commands_in_ignores_comments(self):
        self.assertEqual(commands_in("# op @s"), [])
        self.assertEqual(commands_in("   "), [])


class TestZip(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def mkzip(self, entries):
        z = self.tmp / "p.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return z

    def test_traversal_entries_are_skipped_and_reported(self):
        z = self.mkzip({"pack.mcmeta": "{}", "../../evil.txt": "x", "/abs.txt": "x", "ok/data/a/b.json": "{}"})
        found = extract_zip(z, self.tmp / "out")
        self.assertEqual({f.rule for f in found}, {"ZIP-TRAVERSAL"})
        self.assertFalse((self.tmp / "evil.txt").exists())
        self.assertFalse((self.tmp.parent / "evil.txt").exists())

    def test_zip_bomb_limit(self):
        import wardenpack.archive as a
        old = a.MAX_FILE
        a.MAX_FILE = 1000
        try:
            with self.assertRaises(ScanError):
                extract_zip(self.mkzip({"data/x/big.json": "0" * 5000}), self.tmp / "o2")
        finally:
            a.MAX_FILE = old

    def test_audit_zip_end_to_end(self):
        z = self.mkzip({"gm/pack.mcmeta": "{}", "gm/data/g/function/x.mcfunction": "op @s\n",
                        "gm/data/g/lib.dll": b"MZ" + b"\0" * 80})
        name, rep = audit_target(str(z))
        rules = {f.rule for f in rep.findings}
        self.assertTrue({"ADMIN-OP", "EXE-EXT"} <= rules)
        self.assertTrue(rep.blocking("high", installed_only=False))


class TestPolicy(Base):
    def test_add_blocked_on_high_findings(self):
        url = make_lib(self.tmp, "ops", {"data/o/function/a.mcfunction": "op @s\n"})
        with self.assertRaises(AuditError) as cm:
            self.add(url)
        self.assertIn("ADMIN-OP", str(cm.exception))
        self.assertFalse((self.proj / "data/o").exists())

    def test_fail_on_never_allows_but_shows_in_summary_and_lock(self):
        url = make_lib(self.tmp, "ops2", {"data/o/function/a.mcfunction": "op @s\n"})
        seen = []
        self.add(url, fail_on="never", confirm=lambda lines: seen.extend(lines) or True)
        self.assertTrue(any("ADMIN-OP" in l for l in seen))
        self.assertTrue(any(l.startswith("Audit") and "1 high" in l for l in seen))
        lock = json.loads((self.proj / "warden.lock").read_text())
        self.assertEqual(lock["libraries"]["ops2"]["audit"]["high"], 1)

    def test_executable_is_never_installable(self):
        url = make_lib(self.tmp, "exe", {"data/o/function/a.mcfunction": "say hi\n",
                                         "data/o/helper.exe": "MZ"})
        with self.assertRaises(AuditError):
            self.add(url, fail_on="never")
        self.assertFalse((self.proj / "data/o").exists())

    def test_project_policy_from_manifest(self):
        man = json.loads((self.proj / "warden.json").read_text())
        man["audit"] = {"fail_on": "medium"}
        (self.proj / "warden.json").write_text(json.dumps(man))
        url = make_lib(self.tmp, "gr", {"data/o/function/a.mcfunction": "gamerule doDaylightCycle false\n"})
        with self.assertRaises(AuditError):
            self.add(url)

    def test_clean_library_passes(self):
        url = make_lib(self.tmp, "clean", {"data/c/function/a.mcfunction": "say hi\n"})
        self.assertEqual(self.add(url), "clean")


if __name__ == "__main__":
    unittest.main()
