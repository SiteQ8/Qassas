"""Shared language rules, enforced by the tests.

Arabic text follows the house rule: a period only closes a sentence, clauses
are joined with connectives (و، ف، ثم، أو، لأن، لذا، بل، لكن...) rather than
commas or semicolons, and no Latin punctuation sits inside Arabic prose.
Identifiers such as file names, domains, standards and commands are written in
Latin script and are exempt from those checks, because their dots and colons
are part of the name, not punctuation.

Every English and Arabic pair must carry the same numbers, so a deadline or a
count can never be lost in translation.
"""

import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ARABIC = re.compile("[\u0600-\u06FF]")
DASHES = re.compile("[\u2012\u2013\u2014\u2015\u2212]")
# A Latin identifier: letters, digits and the joiners used in names like laptop.img, ECC-2:2024 or C:\Users.
LATIN_TOKEN = re.compile(r"\.?[A-Za-z0-9][A-Za-z0-9_./:\\@+&%#=?<>-]*[A-Za-z0-9>]|[A-Za-z]")
PLACEHOLDER = re.compile(r"\{[^}]*\}|%[sd]")


def strip_latin(text):
    return LATIN_TOKEN.sub(" ", PLACEHOLDER.sub(" ", text))


def digits(text):
    return sorted(re.findall(r"\d+", PLACEHOLDER.sub(" ", text)))


def arabic_problems(ar, kind):
    """kind is 'sentence' (exactly one closing period) or 'label' (no period)."""
    out = []
    if not ARABIC.search(ar):
        # Numbers and clock times read the same in both languages.
        if not (re.fullmatch(r"[\d:.+ ]+", ar) or LATIN_TOKEN.fullmatch(ar)):
            out.append("Arabic text expected")
        return out
    bare = strip_latin(ar)
    periods = bare.count(".")
    if kind == "sentence":
        if not ar.rstrip().endswith("."):
            out.append("must end with a period")
        if periods != 1:
            out.append("a period may only close the sentence (found %d)" % periods)
    elif periods:
        out.append("a label carries no period")
    if re.search("[\u060C\u061B]", ar):
        out.append("no Arabic comma or semicolon, join clauses with connectives")
    if re.search(r"[,;:!]", bare):
        out.append("no Latin punctuation inside Arabic")
    for tok in LATIN_TOKEN.findall(PLACEHOLDER.sub(" ", ar)):
        if re.fullmatch(r"[a-z]+", tok) and len(tok) > 1:
            out.append("stray lowercase Latin word %r" % tok)
    if re.search(r"\s[.؟]\s*$", ar):
        out.append("space before final punctuation")
    if "  " in ar:
        out.append("double space")
    return out


def pair_problems(en, ar):
    out = []
    if not en or not ar:
        return ["both languages required"]
    if ARABIC.search(en):
        out.append("English text contains Arabic")
    if digits(en) != digits(ar):
        out.append("numbers differ: en %s ar %s" % (digits(en), digits(ar)))
    return out


def pairs(value, path="$", out=None):
    """Every {en, ar} pair anywhere in a value, with its path."""
    out = [] if out is None else out
    if isinstance(value, list):
        for i, v in enumerate(value):
            pairs(v, "%s[%d]" % (path, i), out)
    elif isinstance(value, dict):
        if isinstance(value.get("en"), str) and isinstance(value.get("ar"), str):
            out.append((path, value["en"], value["ar"]))
        for k, v in value.items():
            if k not in ("en", "ar"):
                pairs(v, "%s.%s" % (path, k), out)
    return out


def load_data(name):
    with open(os.path.join(ROOT, "qassas", "data", name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


TEXT_EXT = {".py", ".js", ".mjs", ".json", ".md", ".html", ".css", ".txt", ".xml", ".svg", ".yml", ".yaml", ".toml",
            ".vtt", ".cfg", ".jsonl", ".log", ""}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", "build", "dist"}


def text_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXT or name in ("LICENSE", "CNAME", ".gitignore", ".nojekyll"):
                path = os.path.join(base, name)
                if ext == "" and name not in ("LICENSE", "CNAME", ".gitignore", ".nojekyll"):
                    continue
                yield os.path.relpath(path, ROOT)
