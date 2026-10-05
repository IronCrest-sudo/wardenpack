import json, sys, tempfile, unittest
from datetime import date, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_registry import Base, needs_crypto
from wardenpack.errors import RegistryError
from wardenpack.site import build_site


class TestSite(Base):
    def setUp(self):
        super().setUp()
        self.publish()
        e = json.loads((self.regdir / "libraries/idsys.json").read_text())
        e["description"] = '<script>alert(1)</script> "quoted"'
        (self.regdir / "libraries/idsys.json").write_text(json.dumps(e))
        self.build()
        self.out = self.tmp / "site"

    def test_pages_are_escaped_and_locked_down(self):
        n = build_site(self.regdir / "index.json", self.out, [self.pub])
        self.assertEqual(n, 2)
        for f in ("index.html", "libraries/idsys.html", "style.css", "search.js", "registry/index.json"):
            self.assertTrue((self.out / f).is_file(), f)
        for page in ("index.html", "libraries/idsys.html"):
            t = (self.out / page).read_text()
            self.assertNotIn("<script>alert", t)
            self.assertIn("&lt;script&gt;", t)
            self.assertIn("Content-Security-Policy", t)
            self.assertNotIn("http://", t)
        self.assertIn("warden add idsys", (self.out / "libraries/idsys.html").read_text())
        self.assertEqual((self.out / "registry/index.json").read_bytes(), (self.regdir / "index.json").read_bytes())

    def test_unsigned_or_wrong_key_refused(self):
        with self.assertRaises(RegistryError):
            build_site(self.regdir / "index.json", self.out, ["00" * 32])
        self.assertFalse((self.out / "index.html").exists())

    def test_expired_index_shows_banner(self):
        build_site(self.regdir / "index.json", self.out, [self.pub], today=date.today() + timedelta(days=400))
        self.assertIn("expired", (self.out / "index.html").read_text())


class TestShowcase(unittest.TestCase):
    @needs_crypto
    def test_records_real_gif(self):
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest("Pillow missing")
        from wardenpack.showcase import record
        with tempfile.TemporaryDirectory() as t:
            n = record(Path(t) / "d.gif")
            data = (Path(t) / "d.gif").read_bytes()
            self.assertTrue(data.startswith(b"GIF89a") and n > 10)


if __name__ == "__main__":
    unittest.main()
