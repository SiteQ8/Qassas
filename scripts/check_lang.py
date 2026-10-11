#!/usr/bin/env python3
"""Print every language rule problem in the packaged data. Exit 1 if any."""
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, ROOT)
from helpers import arabic_problems, load_data, pair_problems, pairs  # noqa: E402

LABEL_KEYS = ("title", "term", "objectives", "steps", ".q", "options", "evidence", "questions", "name", "label", "ui.")


def kind_for(path):
    tail = path.split(".")[-1]
    if any(k in path for k in (".why", ".def", ".summary", ".lesson", ".pitfalls", ".kuwait", ".brief", ".synthetic", ".about", ".body")):
        return "sentence"
    if any(k in path for k in LABEL_KEYS) or tail.startswith("q"):
        return "label"
    return "sentence"


def check(name, data, kind=None):
    bad = 0
    for path, en, ar in pairs(data):
        k = kind or kind_for(path)
        probs = arabic_problems(ar, k) + pair_problems(en, ar)
        if probs:
            bad += 1
            print("%s %s %s\n    %s" % (name, path, probs, ar[:160]))
    return bad


def main():
    total = 0
    total += check("glossary", [{"term": t["term"], "def": t["def"]} for t in load_data("glossary")])
    total += check("legal", [{"title": r["title"], "summary": r["summary"]} for r in load_data("legal")])
    total += check("case-01", load_data("case-01"))
    from qassas.data_files import load
    total += check("curriculum", load("curriculum"))
    for extra in ("tools", "ui"):
        try:
            total += check(extra, load_data(extra))
        except FileNotFoundError:
            pass
    print("language problems: %d" % total)
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
