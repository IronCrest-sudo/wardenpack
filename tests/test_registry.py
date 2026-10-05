import json
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_wardenpack import git, make_lib
from wardenpack import ed25519, maintain, registry as reg, semver
from wardenpack.audit import audit_tree
from wardenpack.core import (Project, add_from_registry, check_revocations, init_project, install_all,
                             load_registry, registry_add)
from wardenpack.errors import (IntegrityError, ProjectError, RegistryError, RollbackError, StaleRegistry,
                               UnsafeInput)

needs_crypto = unittest.skipUnless(ed25519.HAVE_CRYPTOGRAPHY, "cryptography not installed")


class TestPrimitives(unittest.TestCase):
    def test_rfc8032_vector_and_tamper(self):
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc"
                            "61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(ed25519._verify_pure(pub, b"", sig))
        self.assertFalse(ed25519._verify_pure(pub, b"x", sig))
        bad_s = sig[:32] + (int.from_bytes(sig[32:], "little") + ed25519.Q).to_bytes(32, "little")
        self.assertFalse(ed25519._verify_pure(pub, b"", bad_s))      # malleated S rejected
        self.assertFalse(ed25519._verify_pure(pub, b"", sig[:-1]))

    @needs_crypto
    def test_pure_matches_library(self):
        for i in range(10):
            seed, pub = ed25519.generate_keypair()
            msg = os.urandom(i * 11)
            sig = ed25519.sign(seed, msg)
            self.assertTrue(ed25519._verify_pure(pub, msg, sig))
            flipped = bytes([sig[0] ^ 1]) + sig[1:]
            self.assertFalse(ed25519._verify_pure(pub, msg, flipped))

    def test_semver(self):
        m = semver.matches
        self.assertTrue(m("1.2.3", "") and m("1.2.3", "latest") and m("1.2.3", "1.2.3"))
        self.assertTrue(m("1.4.0", "^1.2") and not m("2.0.0", "^1.2") and not m("1.1.9", "^1.2"))
        self.assertTrue(m("0.2.5", "^0.2.1") and not m("0.3.0", "^0.2.1"))
        self.assertTrue(m("1.2.9", "~1.2.3") and not m("1.3.0", "~1.2.3"))
        self.assertTrue(m("1.5.0", ">=1.2,<2") and not m("2.0.0", ">=1.2,<2"))
        with self.assertRaises(UnsafeInput):
            m("1.0.0", "garbage")
        with self.assertRaises(UnsafeInput):
            semver.parse("1.0")


@needs_crypto
class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.keyfile = self.tmp / "sign.key"
        self.pub = maintain.keygen(self.keyfile)
        self.regdir = self.tmp / "registry"
        maintain.init_registry(self.regdir, "official")
        self.proj = self.tmp / "proj"
        self.proj.mkdir()
        init_project(self.proj, "mypack", game_version="26.3")
        self.libs = {}

    def tearDown(self):
        self._t.cleanup()

    def lib_repo(self, name, extra=None, version="1.0.0"):
        files = {f"data/{name}/function/a.mcfunction": "say hi\n",
                 "warden.json": {"version": version, "game_version": "26.3"}}
        files.update(extra or {})
        files = {k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in files.items()}
        repo = self.tmp / name
        if not repo.exists():
            return make_lib(self.tmp, name, files)            # one repo per library, like real life
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", f"release {version}")
        return str(repo)

    def publish(self, name="idsys", version="1.0.0", **kw):
        url = self.lib_repo(name, version=version)
        e = maintain.add_lib(self.regdir, name, url, allow_local=True, description="demo", **kw)
        return url, e

    def build(self, **kw):
        return maintain.build(self.regdir, self.keyfile, **kw)

    def client(self, **kw):
        p = Project(self.proj)
        if "official" not in p.manifest.get("registries", {}):
            registry_add(p, "official", str(self.regdir / "index.json"), [self.pub])
        return Project(self.proj)

    def add(self, target, **kw):
        p = self.client()
        return add_from_registry(p, target, allow_local=True, confirm=lambda lines: True, **kw)


class TestIndex(Base):
    def test_valid_roundtrip_and_tamper_detection(self):
        self.publish()
        self.build()
        raw = (self.regdir / "index.json").read_bytes()
        signed = reg.verify_index(raw, [self.pub])
        self.assertEqual(signed["version"], 1)
        env = json.loads(raw)
        env["signed"]["libraries"]["idsys"]["source"] = "https://github.com/evil/repo"
        with self.assertRaises(RegistryError):
            reg.verify_index(json.dumps(env).encode(), [self.pub])
        _, other = ed25519.generate_keypair()
        with self.assertRaises(RegistryError):
            reg.verify_index(raw, [other.hex()])
        with self.assertRaises(RegistryError):                      # threshold 2 with one signature
            reg.verify_index(raw, [self.pub, other.hex()], threshold=2)

    def test_pretty_printing_does_not_matter(self):
        self.publish()
        self.build()
        env = json.loads((self.regdir / "index.json").read_text())
        reg.verify_index(json.dumps(env, indent=7, sort_keys=False).encode(), [self.pub])

    def test_expiry_and_rollback(self):
        self.publish()
        self.build(valid_days=10)
        raw1 = (self.regdir / "index.json").read_bytes()
        later = date.today() + timedelta(days=11)
        with self.assertRaises(StaleRegistry):
            reg.verify_index(raw1, [self.pub], today=later)
        reg.verify_index(raw1, [self.pub], today=later, allow_stale=True)
        self.build()
        self.assertEqual(reg.verify_index((self.regdir / "index.json").read_bytes(), [self.pub])["version"], 2)
        with self.assertRaises(RollbackError):
            reg.verify_index(raw1, [self.pub], last_version=2)

    def test_malformed_signed_payload_rejected(self):
        self.publish()
        self.build()
        env = json.loads((self.regdir / "index.json").read_text())
        env["signed"]["libraries"]["idsys"]["versions"][0]["commit"] = "nothex"
        env["signatures"] = reg.sign_index(env["signed"], bytes.fromhex(self.keyfile.read_text().strip()))["signatures"]
        with self.assertRaises(RegistryError):
            reg.verify_index(json.dumps(env).encode(), [self.pub])


class TestEndToEnd(Base):
    def test_add_from_registry_pins_and_records(self):
        self.publish()
        self.build()
        self.assertEqual(self.add("idsys"), "idsys")
        self.assertTrue((self.proj / "data/idsys/function/a.mcfunction").is_file())
        lock = json.loads((self.proj / "warden.lock").read_text())
        e = lock["libraries"]["idsys"]
        self.assertEqual(e["registry"], {"name": "official", "version": 1, "resolved": "1.0.0"})
        self.assertEqual(lock["registries"]["official"]["version"], 1)
        self.assertEqual(len(e["commit"]), 40)

    def test_version_selection_and_game_version(self):
        self.publish(version="1.0.0")
        self.publish(version="1.1.0")
        self.publish(version="2.0.0")
        self.build()
        self.add("idsys@^1.0")
        lock = json.loads((self.proj / "warden.lock").read_text())
        self.assertEqual(lock["libraries"]["idsys"]["registry"]["resolved"], "1.1.0")

    def test_wrong_game_version_refused(self):
        self.publish(game_version="26.2")
        self.build()
        with self.assertRaises(RegistryError):
            self.add("idsys")

    def test_integrity_mismatch_blocks_install(self):
        self.publish()
        path = self.regdir / "libraries/idsys.json"
        entry = json.loads(path.read_text())
        entry["versions"][0]["integrity"] = "0" * 64
        path.write_text(json.dumps(entry))
        self.build()
        with self.assertRaises(IntegrityError):
            self.add("idsys")
        self.assertFalse((self.proj / "data/idsys").exists())

    def test_registry_cannot_widen_host_allowlist(self):
        self.publish()
        path = self.regdir / "libraries/idsys.json"
        entry = json.loads(path.read_text())
        entry["source"] = "https://evil.example/o/r"
        path.write_text(json.dumps(entry))
        self.build()
        p = self.client()
        with self.assertRaises(UnsafeInput):
            add_from_registry(p, "idsys", confirm=lambda l: True)

    def test_revocation_blocks_and_flags(self):
        _, e = self.publish(version="1.0.0")
        self.build()
        self.add("idsys")
        (self.regdir / "revocations.json").write_text(json.dumps(
            [{"id": "idsys", "version": "1.0.0", "reason": "backdoor found"}]))
        self.build()
        problems = check_revocations(self.client(), refresh=True)
        self.assertTrue(any("REVOKED" in x and "backdoor" in x for x in problems))
        # and a fresh project cannot resolve the revoked version
        other = self.tmp / "p2"
        other.mkdir()
        init_project(other, "p2")
        p2 = Project(other)
        registry_add(p2, "official", str(self.regdir / "index.json"), [self.pub])
        with self.assertRaises(RegistryError) as cm:
            add_from_registry(Project(other), "idsys", allow_local=True, confirm=lambda l: True)
        self.assertIn("REVOKED", str(cm.exception))

    def test_rollback_detected_by_client(self):
        self.publish()
        self.build()
        old = (self.regdir / "index.json").read_bytes()
        self.add("idsys")
        self.publish(version="1.1.0")
        self.build()
        p = self.client()
        load_registry(p, "official")                                # sees v2 ...
        p.save()                                                    # ... and remembers it in warden.lock
        (self.regdir / "index.json").write_bytes(old)               # attacker serves the old index
        with self.assertRaises(RollbackError):
            load_registry(Project(self.proj), "official")

    def test_install_restores_registry_lib_without_registry_access(self):
        self.publish()
        self.build()
        self.add("idsys")
        import shutil
        shutil.rmtree(self.proj / "data/idsys")
        (self.regdir / "index.json").unlink()                        # registry gone entirely
        res = install_all(Project(self.proj), allow_local=True)
        self.assertTrue(res[0][1].startswith("restored"))
        self.assertTrue((self.proj / "data/idsys/function/a.mcfunction").is_file())

    def test_unknown_registry_and_no_registry(self):
        p = Project(self.proj)
        with self.assertRaises(ProjectError):
            add_from_registry(p, "idsys")


class TestMaintain(Base):
    def test_versions_are_immutable(self):
        self.publish(version="1.0.0")
        url2 = self.lib_repo("idsys", extra={"data/idsys/function/b.mcfunction": "say b"}, version="1.0.0")  # same version, new commit
        with self.assertRaises(RegistryError):
            maintain.add_lib(self.regdir, "idsys", url2, allow_local=True)

    def test_add_lib_refuses_high_findings(self):
        url = self.lib_repo("bad", extra={"data/bad/function/o.mcfunction": "op @s\n"})
        from wardenpack.errors import AuditError
        with self.assertRaises(AuditError):
            maintain.add_lib(self.regdir, "bad", url, allow_local=True)
        self.assertFalse((self.regdir / "libraries/bad.json").exists())

    def test_check_detects_drift(self):
        self.publish()
        self.assertEqual(maintain.check(self.regdir, allow_local=True), [])
        path = self.regdir / "libraries/idsys.json"
        entry = json.loads(path.read_text())
        entry["versions"][0]["integrity"] = "f" * 64
        path.write_text(json.dumps(entry))
        self.assertTrue(maintain.check(self.regdir, allow_local=True))

    def test_keygen_never_overwrites_and_is_private(self):
        with self.assertRaises(FileExistsError):
            maintain.keygen(self.keyfile)
        if os.name == "posix":
            self.assertEqual(self.keyfile.stat().st_mode & 0o777, 0o600)


class TestNewAuditRules(unittest.TestCase):
    def test_rules_from_core_scanner(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "data/x/function").mkdir(parents=True)
            (root / "data/x/function/a.mcfunction").write_text(
                "data merge storage minecraft:foo {a:1}\ndata merge entity @a {x:1}\n")
            (root / "data/minecraft/tags/function").mkdir(parents=True)
            (root / "data/minecraft/tags/function/tick.json").write_text(
                json.dumps({"values": [f"x:f{i}" for i in range(25)]}))
            rules = {f.rule for f in audit_tree(root).findings}
            self.assertTrue({"DATA-VANILLA-STORAGE", "DATA-MERGE-BROAD", "MANY-TICK", "HOOK-TICK"} <= rules)

    def test_init_writes_modern_pack_mcmeta(self):
        with tempfile.TemporaryDirectory() as t:
            notes = init_project(t, "demo")
            pack = json.loads((Path(t) / "pack.mcmeta").read_text())["pack"]
            self.assertEqual((pack["min_format"], pack["max_format"]), (122, 122))
            self.assertNotIn("pack_format", pack)
            self.assertTrue(any("122" in n for n in notes))


if __name__ == "__main__":
    unittest.main()
