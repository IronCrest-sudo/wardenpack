import gzip
import io
import json
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_audit import tree
from wardenpack.audit import audit_tree, commands_in
from wardenpack.cli import main
from wardenpack.errors import ScanError, UnsafeInput
from wardenpack.safety import validate_rel, windows_hazard
from wardenpack.scan import scan


def nbt_with_command(cmd: str) -> bytes:
    """Minimal NBT blob carrying a TAG_String named 'Command' (what a command block stores)."""
    c = cmd.encode()
    body = b"\x0a\x00\x00" + b"\x08\x00\x07Command" + struct.pack(">H", len(c)) + c + b"\x00"
    return gzip.compress(body)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def rules(self, files):
        self._n = getattr(self, "_n", 0) + 1
        return {f.rule for f in audit_tree(tree(self.root / f"p{self._n}", files)).findings}


class TestNamespacedCommands(Base):
    def test_minecraft_prefix_cannot_hide_command(self):
        self.assertIn("ADMIN-OP", self.rules({"data/x/function/a.mcfunction": "minecraft:op @s"}))

    def test_minecraft_prefix_cannot_hide_execute_unwrapping(self):
        r = self.rules({"data/x/function/a.mcfunction": "/minecraft:execute as @a run minecraft:stop"})
        self.assertIn("ADMIN-STOP", r)

    def test_unwrapping_still_correct(self):
        self.assertEqual(commands_in("minecraft:execute as @a run say hi")[0][0], "say")


class TestNewRules(Base):
    def test_tick_control(self):
        self.assertIn("TICK-CTL", self.rules({"data/x/function/a.mcfunction": "tick rate 1"}))
        self.assertIn("TICK-CTL", self.rules({"data/x/function/b.mcfunction": "tick freeze"}))
        self.assertNotIn("TICK-CTL", self.rules({"data/x/function/c.mcfunction": "tick query"}))

    def test_command_block_injection_and_inner_command(self):
        line = 'setblock ~ ~ ~ command_block{Command:"op @p",auto:1b}'
        r = self.rules({"data/x/function/a.mcfunction": line})
        self.assertIn("CMDBLOCK-INJECT", r)
        self.assertIn("CMDBLOCK-ADMIN-OP", r)

    def test_command_minecart_summon(self):
        line = "summon command_block_minecart ~ ~ ~ {Command:'stop'}"
        r = self.rules({"data/x/function/a.mcfunction": line})
        self.assertIn("CMDBLOCK-ADMIN-STOP", r)

    def test_embedded_depth_is_bounded(self):
        inner = 'setblock ~ ~ ~ command_block{Command:\\"op @p\\"}'
        outer = 'setblock ~ ~ ~ command_block{Command:"%s"}' % inner.replace('"', '\\"').replace("\\\\", "\\")
        self.rules({"data/x/function/a.mcfunction": outer})   # must terminate without error

    def test_plain_setblock_is_clean(self):
        self.assertEqual(self.rules({"data/x/function/a.mcfunction": "setblock ~ ~ ~ stone"}), set())


class TestJsonActions(Base):
    def test_dialog_run_command(self):
        doc = {"type": "minecraft:notice", "action": {"type": "run_command", "command": "op @s"}}
        r = self.rules({"data/x/dialog/d.json": json.dumps(doc)})
        self.assertIn("CLICK-RUN", r)
        self.assertIn("CLICK-ADMIN-OP", r)

    def test_click_event_in_book_component(self):
        doc = {"pages": [{"text": "x", "click_event": {"action": "run_command", "command": "/stop"}}]}
        self.assertIn("CLICK-ADMIN-STOP", self.rules({"data/x/loot_table/b.json": json.dumps(doc)}))

    def test_suggest_command_is_not_flagged(self):
        doc = {"click_event": {"action": "suggest_command", "command": "/op @s"}}
        self.assertNotIn("CLICK-RUN", self.rules({"data/x/dialog/d.json": json.dumps(doc)}))

    def test_deeply_nested_json_does_not_recurse(self):
        s = "[" * 50000 + "]" * 50000
        self.assertIn("JSON-DEEP", self.rules({"data/x/dialog/d.json": s}))

    def test_deep_json_tag_is_a_scan_error_not_a_crash(self):
        d = self.root / "lib/data/minecraft/tags/function"
        d.mkdir(parents=True)
        (d / "tick.json").write_text("[" * 50000 + "]" * 50000)
        with self.assertRaises(ScanError):
            scan(self.root / "lib")


class TestNbt(Base):
    def test_structure_command_block(self):
        r = self.rules({"data/x/structure/s.nbt": nbt_with_command("op @a")})
        self.assertIn("CMDBLOCK-NBT", r)
        self.assertIn("CMDBLOCK-ADMIN-OP", r)

    def test_benign_structure(self):
        body = gzip.compress(b"\x0a\x00\x00\x00")
        self.assertEqual(self.rules({"data/x/structure/s.nbt": body}), set())

    def test_gzip_bomb_is_bounded(self):
        bomb = gzip.compress(b"\x00" * (40 * 1024 * 1024), 9)
        self.assertIn("NBT-BOMB", self.rules({"data/x/structure/s.nbt": bomb}))

    def test_corrupt_gzip(self):
        self.assertIn("NBT-CORRUPT", self.rules({"data/x/structure/s.nbt": b"\x1f\x8bgarbage"}))

    def test_snbt_command(self):
        r = self.rules({"data/x/structure/s.snbt": '{Command:"stop"}'})
        self.assertIn("CMDBLOCK-ADMIN-STOP", r)


class TestPathHazards(Base):
    def test_windows_names(self):
        for bad in ("data/x/function/con.mcfunction", "data/x/aux", "data/x/function/NUL.txt",
                    "data/x/function/evil.exe.", "data/x/f:stream"):
            self.assertIsNotNone(windows_hazard(bad), bad)
        self.assertIsNone(windows_hazard("data/x/function/console.mcfunction"))
        self.assertIsNone(windows_hazard("data/x/function/a/b.mcfunction"))

    def test_validate_rel_rejects_hazard(self):
        with self.assertRaises(UnsafeInput):
            validate_rel("data/x/function/con.mcfunction")
        with self.assertRaises(UnsafeInput):
            validate_rel("data/x/function/a.json.")
        self.assertEqual(validate_rel("data/x/function/a.mcfunction"), "data/x/function/a.mcfunction")

    def test_audit_flags_win_name(self):
        self.assertIn("WIN-NAME", self.rules({"data/x/function/prn.mcfunction": "say hi"}))

    def test_case_collision_in_audit(self):
        (self.root / "data/x/function").mkdir(parents=True)
        (self.root / "data/x/function/A.mcfunction").write_text("say a")
        (self.root / "data/x/function/a.mcfunction").write_text("say b")
        r = {f.rule for f in audit_tree(self.root).findings}
        self.assertIn("CASE-COLLISION", r)

    def test_case_collision_blocks_install_scan(self):
        (self.root / "data/x/function").mkdir(parents=True)
        (self.root / "data/x/function/A.mcfunction").write_text("say a")
        (self.root / "data/x/function/a.mcfunction").write_text("say b")
        with self.assertRaises(ScanError):
            scan(self.root)


class TestSarif(Base):
    def test_sarif_output_shape_and_exit_code(self):
        tree(self.root, {"data/x/function/a.mcfunction": "op @s\nsay hi"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["audit", str(self.root), "--format", "sarif"])
        doc = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "wardenpack")
        res = [r for r in run["results"] if r["ruleId"] == "ADMIN-OP"][0]
        self.assertEqual(res["level"], "error")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "data/x/function/a.mcfunction")
        self.assertEqual(loc["region"]["startLine"], 1)
        self.assertEqual(res["ruleIndex"], [r["id"] for r in run["tool"]["driver"]["rules"]].index("ADMIN-OP"))

    def test_sarif_clean_pack(self):
        tree(self.root, {"data/x/function/a.mcfunction": "say hi"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["audit", str(self.root), "--format", "sarif"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
