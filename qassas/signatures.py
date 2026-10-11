"""Identify files by their content, not their name.

A file's extension is a label anyone can change. The first bytes of most
formats, the magic number or signature, are fixed by the format itself.
Comparing the two finds renamed files, a classic way to hide an archive or a
program among photos.
"""

import io
import os
import zipfile

from .data_files import load

HEAD = 40 * 1024  # enough to reach the ISO 9660 descriptor at 32769


def _signatures():
    sigs = []
    for s in load("signatures"):
        s = dict(s)
        s["magic"] = bytes.fromhex(s["hex"])
        if "also" in s:
            s["also_magic"] = bytes.fromhex(s["also"]["hex"])
        sigs.append(s)
    # Longer and more specific signatures first, so PNG beats nothing and
    # an Office file beats a plain ZIP.
    sigs.sort(key=lambda s: (-(len(s["magic"]) + (8 if "also" in s or "zip_member" in s else 0)), s["id"]))
    return sigs


SIGNATURES = _signatures()


def _zip_members(data, path):
    try:
        if path:
            with zipfile.ZipFile(path) as zf:
                return set(zf.namelist())
        return set(zipfile.ZipFile(io.BytesIO(data)).namelist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return set()


def match(head, path=None, full=None):
    """Return the best matching signature dictionary for these leading bytes."""
    members = None
    for sig in SIGNATURES:
        start = sig["offset"]
        if head[start:start + len(sig["magic"])] != sig["magic"]:
            continue
        if "also" in sig:
            o = sig["also"]["offset"]
            if head[o:o + len(sig["also_magic"])] != sig["also_magic"]:
                continue
        if "zip_member" in sig:
            if members is None:
                members = _zip_members(full, path)
            if sig["zip_member"] not in members:
                continue
        return sig
    return None


def identify_bytes(data, name=""):
    return _verdict(match(data[:HEAD], full=data), name, data[:16])


def identify(path):
    with open(path, "rb") as fh:
        head = fh.read(HEAD)
    return _verdict(match(head, path=path), os.path.basename(path), head[:16])


def _verdict(sig, name, first):
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    result = {
        "name": name,
        "extension": ext,
        "first_bytes": first.hex(" "),
        "detected": sig["id"] if sig else None,
        "description": sig["name"] if sig else None,
        "expected_extensions": sig["ext"] if sig else [],
    }
    if sig is None:
        result["status"] = "unknown"
    elif ext in sig["ext"] or (ext == "" and "" in sig["ext"]):
        result["status"] = "match"
    else:
        result["status"] = "mismatch"
    return result


def scan(root):
    """Identify every file under root and return the verdicts."""
    out = []
    for base, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(base, name)
            verdict = identify(full)
            verdict["path"] = os.path.relpath(full, root).replace(os.sep, "/")
            out.append(verdict)
    return out
