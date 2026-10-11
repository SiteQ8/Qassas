"""Hashing and evidence manifests.

An examiner hashes every item at acquisition and again before analysis. If the
two values match, the copy is bit for bit the same as what was seized. A
manifest records the hashes of a whole evidence folder so anyone can repeat
the check later.
"""

import hashlib
import json
import os
from datetime import datetime

from . import __version__
from .timeutil import UTC, iso

ALGORITHMS = ("md5", "sha1", "sha256")
CHUNK = 1 << 20


def hash_bytes(data, algorithms=ALGORITHMS):
    return {name: hashlib.new(name, data).hexdigest() for name in algorithms}


def hash_file(path, algorithms=ALGORITHMS):
    """Hash a file in one streaming pass with several algorithms."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            size += len(block)
            for h in hashers.values():
                h.update(block)
    result = {name: h.hexdigest() for name, h in hashers.items()}
    result["size"] = size
    return result


def _walk(root):
    for base, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            yield rel, full


def make_manifest(root, case=None, examiner=None, exclude=("manifest.json",)):
    """Hash every file under root and return a manifest dictionary."""
    entries = []
    for rel, full in _walk(root):
        if rel in exclude:
            continue
        h = hash_file(full)
        entries.append({"path": rel, "size": h["size"], "md5": h["md5"],
                        "sha1": h["sha1"], "sha256": h["sha256"]})
    return {
        "format": "qassas-manifest/1",
        "tool": "qassas " + __version__,
        "created_utc": iso(datetime.now(UTC)),
        "case": case,
        "examiner": examiner,
        "files": entries,
    }


def write_manifest(manifest, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def sha256sum_lines(manifest):
    """The same manifest in the format GNU sha256sum -c understands."""
    return "".join("%s  %s\n" % (f["sha256"], f["path"]) for f in manifest["files"])


def verify_manifest(manifest, root):
    """Compare a folder with its manifest.

    Returns a dictionary with ok, modified, missing and extra lists. A file
    counts as modified when its SHA-256 differs from the manifest.
    """
    listed = {f["path"]: f for f in manifest["files"]}
    present = dict(_walk(root))
    present.pop("manifest.json", None)
    report = {"ok": [], "modified": [], "missing": [], "extra": []}
    for rel, entry in listed.items():
        if rel not in present:
            report["missing"].append(rel)
            continue
        actual = hash_file(present[rel])
        if actual["sha256"] == entry["sha256"]:
            report["ok"].append(rel)
        else:
            report["modified"].append({"path": rel, "expected": entry["sha256"], "actual": actual["sha256"]})
    report["extra"] = sorted(set(present) - set(listed))
    report["passed"] = not (report["modified"] or report["missing"] or report["extra"])
    return report
