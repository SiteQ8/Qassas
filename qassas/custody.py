"""A hash chained chain of custody log.

Each entry records who held an evidence item, what they did with it, when and
where. Every entry stores the SHA-256 of the entry before it, and its own hash
covers all its fields, so editing, deleting or reordering any entry breaks the
chain at that point and the verifier says exactly where.

The log is JSON Lines: one entry per line, appended and never rewritten.
"""

import hashlib
import json
from datetime import datetime

from .timeutil import UTC, iso, parse_iso

ACTIONS = ("seized", "sealed", "transferred", "received", "opened", "imaged",
           "verified", "analysed", "resealed", "returned", "stored")
GENESIS = "0" * 64
FIELDS = ("seq", "time_utc", "action", "item", "by", "to", "location", "note", "item_sha256", "prev")


def canonical(entry):
    """Stable bytes for hashing: the fixed fields only, sorted keys, UTF-8."""
    body = {k: entry.get(k) for k in FIELDS}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def entry_hash(entry):
    return hashlib.sha256(canonical(entry)).hexdigest()


def read(path):
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def make_entry(entries, action, item, by, to=None, location=None, note=None,
               item_sha256=None, time_utc=None):
    if action not in ACTIONS:
        raise ValueError("unknown action %r, expected one of %s" % (action, ", ".join(ACTIONS)))
    prev = entries[-1]["hash"] if entries else GENESIS
    entry = {
        "seq": len(entries) + 1,
        "time_utc": time_utc or iso(datetime.now(UTC)),
        "action": action,
        "item": item,
        "by": by,
        "to": to,
        "location": location,
        "note": note,
        "item_sha256": item_sha256,
        "prev": prev,
    }
    entry["hash"] = entry_hash(entry)
    return entry


def append(path, **kwargs):
    try:
        entries = read(path)
    except FileNotFoundError:
        entries = []
    entry = make_entry(entries, **kwargs)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify(entries):
    """Check the whole chain and return a list of problems, empty when sound.

    Each problem is a dictionary with the sequence number, a code and the
    expected and actual values where they apply, so a report can explain it.
    """
    problems = []
    prev_hash = GENESIS
    prev_time = None
    hashes_by_item = {}
    for index, entry in enumerate(entries):
        seq = entry.get("seq")
        if seq != index + 1:
            problems.append({"seq": seq, "code": "sequence", "expected": index + 1, "actual": seq})
        if entry.get("prev") != prev_hash:
            problems.append({"seq": seq, "code": "broken_link", "expected": prev_hash, "actual": entry.get("prev")})
        actual = entry_hash(entry)
        if entry.get("hash") != actual:
            problems.append({"seq": seq, "code": "entry_altered", "expected": entry.get("hash"), "actual": actual})
        try:
            when = parse_iso(entry["time_utc"])
            if prev_time and when < prev_time:
                problems.append({"seq": seq, "code": "time_reversed", "expected": iso(prev_time), "actual": entry["time_utc"]})
            prev_time = when
        except (KeyError, ValueError):
            problems.append({"seq": seq, "code": "bad_time", "expected": "ISO 8601", "actual": entry.get("time_utc")})
        digest = entry.get("item_sha256")
        if digest:
            seen = hashes_by_item.get(entry.get("item"))
            if seen and seen != digest:
                problems.append({"seq": seq, "code": "item_hash_changed", "expected": seen, "actual": digest})
            hashes_by_item.setdefault(entry.get("item"), digest)
        prev_hash = entry.get("hash")
    return problems


EXPLAIN = {
    "sequence": {"en": "an entry is missing or out of order",
                 "ar": "يوجد قيد مفقود أو قيد في غير موضعه"},
    "broken_link": {"en": "this entry does not point to the hash of the entry before it",
                    "ar": "لا يشير هذا القيد إلى بصمة القيد الذي يسبقه"},
    "entry_altered": {"en": "this entry was changed after it was written",
                      "ar": "عُدّل هذا القيد بعد كتابته"},
    "time_reversed": {"en": "this entry is dated before the entry above it",
                      "ar": "تاريخ هذا القيد أسبق من تاريخ القيد الذي قبله"},
    "bad_time": {"en": "the time is missing or not ISO 8601",
                 "ar": "الوقت مفقود أو مكتوب بغير صيغة ISO 8601"},
    "item_hash_changed": {"en": "the item's SHA-256 differs from the first value recorded for it",
                          "ar": "تختلف بصمة SHA-256 للدليل عن أول قيمة سُجّلت له"},
}
