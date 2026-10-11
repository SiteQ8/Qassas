"""Integrity of every piece of content: language rules, numbers, references, assets."""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import ROOT, arabic_problems, load_data, pair_problems, pairs  # noqa: E402

sys.path.insert(0, ROOT)
from qassas.data_files import load  # noqa: E402

SENTENCE_KEYS = (".why", ".def", ".summary", ".lesson", ".pitfalls", ".kuwait", ".brief", ".synthetic", ".intro", ".method", ".author")


def kind_for(path, en):
    if any(k in path for k in SENTENCE_KEYS):
        return "sentence"
    return "sentence" if en.rstrip().endswith(".") and not en.rstrip().endswith("..") else "label"


def site(name):
    with open(os.path.join(ROOT, "site", name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


class LanguageTests(unittest.TestCase):
    def check(self, name, data, by_arabic=False):
        problems = []
        for path, en, ar in pairs(data):
            kind = ("sentence" if ar.rstrip().endswith(".") else "label") if by_arabic else kind_for(path, en)
            probs = arabic_problems(ar, kind) + pair_problems(en, ar)
            if probs:
                problems.append("%s %s: %s | %s" % (name, path, "; ".join(probs), ar[:90]))
        self.assertEqual(problems, [], "\n".join(problems))

    def test_curriculum(self):
        self.check("curriculum", load("curriculum"))

    def test_glossary(self):
        self.check("glossary", load_data("glossary"))

    def test_legal(self):
        self.check("legal", [{"title": r["title"], "summary": r["summary"]} for r in load_data("legal")])

    def test_case(self):
        self.check("case", load_data("case-01"))

    def test_tools(self):
        self.check("tools", load_data("tools"))

    def test_site_text(self):
        self.check("ui", site("ui"), by_arabic=True)
        self.check("site", site("site"), by_arabic=True)

    def test_the_rule_itself(self):
        self.assertTrue(arabic_problems("جملة أولى. جملة ثانية.", "sentence"))
        self.assertTrue(arabic_problems("جملة، فيها فاصلة.", "sentence"))
        self.assertTrue(arabic_problems("بها: نقطتان.", "sentence"))
        self.assertTrue(arabic_problems("كلمة stray هنا.", "sentence"))
        self.assertFalse(arabic_problems("افتح الملف laptop.img ثم احسب بصمة SHA-256 له.", "sentence"))
        self.assertTrue(pair_problems("within 72 hours", "خلال 24 ساعة"))


class CurriculumTests(unittest.TestCase):
    def setUp(self):
        self.mods = load("curriculum")["modules"]

    def test_order_and_ids(self):
        self.assertEqual([m["n"] for m in self.mods], list(range(1, len(self.mods) + 1)))
        self.assertEqual(len({m["id"] for m in self.mods}), len(self.mods))

    def test_shape(self):
        for m in self.mods:
            self.assertGreaterEqual(len(m["lesson"]), 4, m["id"])
            self.assertGreaterEqual(len(m["steps"]), 4, m["id"])
            self.assertEqual(len(m["objectives"]), 3, m["id"])
            self.assertGreaterEqual(len(m["quiz"]), 2, m["id"])
            for q in m["quiz"]:
                self.assertEqual(len(q["options"]), 4, m["id"])
                self.assertIn(q["answer"], range(4), m["id"])

    def test_references_resolve(self):
        laws = {r["id"] for r in load_data("legal")}
        terms = {t["id"] for t in load_data("glossary")}
        tools = {t["id"] for t in load_data("tools")["tools"]}
        labs = {l["id"] for l in site("site")["labs"]}
        for m in self.mods:
            self.assertTrue(set(m["law_refs"]) <= laws, m["id"])
            self.assertTrue(set(m["terms"]) <= terms, m["id"])
            self.assertTrue(set(m["tools"]) <= tools, m["id"])
            if m["lab"]:
                self.assertIn(m["lab"], labs, m["id"])
            for size in ("", "-sm"):
                self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", "media", "scenes", m["image"] + size + ".jpg")), m["image"])

    def test_every_lab_points_at_a_module_that_points_back(self):
        mods = {m["id"]: m for m in self.mods}
        for lab in site("site")["labs"]:
            self.assertEqual(mods[lab["module"]]["lab"], lab["id"])

    def test_commands_are_real(self):
        from qassas.cli import build_parser
        commands = {a.dest: a for a in build_parser()._subparsers._group_actions}["cmd"].choices
        for m in self.mods:
            for c in m["commands"]:
                self.assertIn(c.split()[1], commands, c)


class ReferenceDataTests(unittest.TestCase):
    def test_glossary(self):
        g = load_data("glossary")
        mods = {m["id"] for m in load("curriculum")["modules"]}
        self.assertEqual(len({t["id"] for t in g}), len(g))
        for t in g:
            self.assertIn(t["module"], mods, t["id"])

    def test_legal(self):
        rows = load_data("legal")
        self.assertEqual(len({r["id"] for r in rows}), len(rows))
        for r in rows:
            self.assertIn(r["country"], ("KW", "SA", "AE", "QA", "BH", "OM", "INTL"), r["id"])
            self.assertIn(r["type"], ("law", "regulation", "decision", "framework", "court"), r["id"])
            self.assertTrue(r["source"]["url"].startswith("https://"), r["id"])
            self.assertTrue(1960 <= r["year"] <= 2026, r["id"])
            self.assertTrue(r["notes_en"], r["id"])
        self.assertGreaterEqual(sum(r["country"] == "KW" for r in rows), 10)

    def test_tools(self):
        d = load_data("tools")
        cats = {c["id"] for c in d["categories"]}
        for t in d["tools"]:
            self.assertIn(t["category"], cats, t["id"])
            self.assertTrue(t["url"].startswith("https://"), t["id"])
            self.assertTrue(t["license"], t["id"])
        for c in cats:
            self.assertTrue(any(t["category"] == c for t in d["tools"]), c)

    def test_signatures(self):
        sigs = load_data("signatures")
        self.assertEqual(len({s["id"] for s in sigs}), len(sigs))
        for s in sigs:
            bytes.fromhex(s["hex"])

    def test_case_questions(self):
        c = load_data("case-01")
        mods = {m["id"] for m in load("curriculum")["modules"]}
        for q in c["questions"]:
            self.assertIn(q["module"], mods, q["id"])
            self.assertTrue(q["command"].startswith("qassas "), q["id"])

    def test_media_list(self):
        for m in site("site")["media"]:
            self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", "media", "scenes", m["id"] + "-sm.jpg")), m["id"])


class UiKeyTests(unittest.TestCase):
    def test_every_key_used_exists_and_every_key_is_used(self):
        ui = site("ui")
        with open(os.path.join(ROOT, "docs", "assets", "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        with open(os.path.join(ROOT, "docs", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        used = set(re.findall(r"\bt\('([a-z0-9_.]+)'", js)) | set(re.findall(r'data-t(?:-aria)?="([a-z0-9_.]+)"', html))
        used |= {k for k in re.findall(r"'([a-z0-9_.]+)'", js) if k in ui}
        used = {k for k in used if not k.endswith(".")}
        missing = sorted(used - set(ui))
        self.assertEqual(missing, [])
        prefixes = set(re.findall(r"\bt\('([a-z]+\.)' \+", js))
        unused = sorted(k for k in ui if k not in used and not any(k.startswith(p) for p in prefixes))
        self.assertEqual(unused, [])


if __name__ == "__main__":
    unittest.main()
