"""Repository wide gates. These protect rules that hold for every file, not one module."""

import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import DASHES, ROOT, text_files  # noqa: E402

sys.path.insert(0, ROOT)
import qassas  # noqa: E402

# Built from pieces so this file does not trip its own checks.
ATTRIBUTION = re.compile(r"\b(" + "|".join(["cla" + "ude", "anth" + "ropic", "co-authored" + "-by", "generated with " + "cla"]) + r")", re.I)
FORBIDDEN_NAME = re.compile(r"\b" + "N" + "BK" + r"\b|National Bank of " + "Kuwait", re.I)
SECRET = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[0-9a-zA-Z]{10,}")
UNFINISHED = re.compile(r"\b(" + "|".join(["TO" + "DO", "FIX" + "ME", "X" * 3]) + r")\b")


def contents():
    for rel in text_files():
        with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
            yield rel, fh.read()


class GateTests(unittest.TestCase):
    def test_no_unicode_dashes(self):
        bad = [rel for rel, text in contents() if DASHES.search(text)]
        self.assertEqual(bad, [])

    def test_no_assistant_attribution(self):
        bad = [rel for rel, text in contents() if ATTRIBUTION.search(text)]
        self.assertEqual(bad, [])

    def test_no_forbidden_name(self):
        bad = [rel for rel, text in contents() if FORBIDDEN_NAME.search(text)]
        self.assertEqual(bad, [])

    def test_no_secrets(self):
        bad = [rel for rel, text in contents() if SECRET.search(text)]
        self.assertEqual(bad, [])

    def test_no_unfinished_markers(self):
        bad = [rel for rel, text in contents() if UNFINISHED.search(text)]
        self.assertEqual(bad, [])

    def test_versions_agree(self):
        v = qassas.__version__
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
            self.assertIn('version = "%s"' % v, fh.read())
        with open(os.path.join(ROOT, "package.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["version"], v)
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
            self.assertIn("## %s " % v, fh.read())
        with open(os.path.join(ROOT, "docs", "data", "bundle.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["version"], v)

    def test_required_files(self):
        for rel in ("LICENSE", "NOTICE.md", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "docs/CNAME",
                    "docs/.nojekyll", "docs/favicon.svg", "docs/og.png", "docs/robots.txt", "docs/sitemap.xml", "docs/fonts/OFL.txt",
                    "docs/media/explainer/qassas-explainer-ar.mp4", "docs/media/explainer/qassas-explainer-en.mp4"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)

    def test_cname(self):
        with open(os.path.join(ROOT, "docs", "CNAME"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().strip(), "qassas.3li.info")

    def test_generated_site_is_current(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_site.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_captions_are_current(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "explainer", "build.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_site_references_exist(self):
        with open(os.path.join(ROOT, "docs", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        refs = re.findall(r'(?:href|src)="((?:assets|fonts|data|media)/[^"]+)"', html)
        with open(os.path.join(ROOT, "docs", "assets", "styles.css"), encoding="utf-8") as fh:
            refs += [r.replace("../", "") for r in re.findall(r"url\((\.\./fonts/[^)]+)\)", fh.read())]
        for ref in refs:
            self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", ref)), ref)

    def test_site_weight(self):
        total = 0
        for base, _dirs, files in os.walk(os.path.join(ROOT, "docs")):
            total += sum(os.path.getsize(os.path.join(base, f)) for f in files)
        self.assertLess(total, 60 * 1024 * 1024)

    def test_practice_data_stays_synthetic(self):
        with open(os.path.join(ROOT, "qassas", "lab.py"), encoding="utf-8") as fh:
            src = fh.read()
        for domain in re.findall(r'"([a-z0-9.-]+\.[a-z]{2,})"', src):
            if "." in domain and not domain.endswith((".py", ".json", ".exe", ".img", ".zip", ".pdf", ".jpg", ".log", ".jsonl", ".pcap", ".txt", ".lnk")):
                self.assertTrue(domain.endswith(".example"), domain)
        for ip in re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', src):
            self.assertTrue(ip.startswith(("10.", "192.0.2.", "198.51.100.", "203.0.113.")), ip)


if __name__ == "__main__":
    unittest.main()
