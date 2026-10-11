#!/usr/bin/env python3
"""Build everything the website serves from the versioned sources.

Writes:
  docs/data/bundle.json      lessons, glossary, law, tools, labs, case, timeline, UI text
  docs/labs/case-01.zip      the full practice case, byte for byte reproducible
  docs/labs/case-01/...      the few case files the in-browser labs open directly

With --check nothing is written: the build runs in a temporary folder and the
command fails if any served file differs from what is committed. Generated
files are never edited by hand.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from qassas import __version__, carve, examine, geo, lab  # noqa: E402
from qassas.custody import EXPLAIN  # noqa: E402
from qassas.data_files import load  # noqa: E402

DOCS = os.path.join(ROOT, "docs")
SAMPLES = [
    "evidence/Documents/invoice_0921.jpg",
    "evidence/Documents/Tender_2026_Final.pdf",
    "evidence/Pictures/IMG_2038.jpg",
    "evidence/Recent/Tender_Update.lnk",
    "evidence/Network/capture.pcap",
    "custody/custody.jsonl",
    "custody/custody_archive_copy.jsonl",
    "questions.json",
]
ZIP_TIME = (2026, 10, 4, 15, 5, 0)


def read_json(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return json.load(fh)


def make_zip(case_dir):
    """Zip the case with fixed times, permissions and order so the bytes never change."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        names = []
        for base, dirs, files in os.walk(case_dir):
            dirs.sort()
            for f in sorted(files):
                names.append(os.path.relpath(os.path.join(base, f), case_dir).replace(os.sep, "/"))
        for name in sorted(names):
            info = zipfile.ZipInfo("qassas-case-01/" + name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(os.path.join(case_dir, name), "rb") as fh:
                zf.writestr(info, fh.read())
    return buf.getvalue()


def pivots(events):
    """Tag the moments a student should find first. Each tag is applied once, to the first match."""
    rules = [
        ("phish", lambda e: e["source"] == "browser" and e["type"] == "visit" and lab.PHISH_DOMAIN in e.get("url", "")),
        ("download", lambda e: e["source"] == "browser" and e["type"] == "download"),
        ("execution", lambda e: e["source"] == "windows" and e["type"] == "process_created" and "update.exe" in e["description"]),
        ("persistence", lambda e: e["source"] == "windows" and e["type"] == "service_installed"),
        ("beacon", lambda e: e["source"] == "network" and e["type"] == "dns_query" and lab.C2_DOMAIN in e["description"]),
        ("exfil", lambda e: e["source"] == "network" and e["type"] == "http" and "POST" in e["description"]),
        ("guessing", lambda e: e["source"] == "auth_log" and e["type"] == "ssh_failed" and e.get("ip") == lab.ATTACKER_IP),
        ("login", lambda e: e["source"] == "auth_log" and e["type"] == "ssh_accepted" and e.get("ip") == lab.ATTACKER_IP),
        ("cleared", lambda e: e["source"] == "windows" and e["type"] == "log_cleared"),
    ]
    out = []
    used = set()
    for e in events:
        item = {k: e[k] for k in ("time_utc", "source", "type", "description", "artifact")}
        for name, test in rules:
            if name not in used and test(e):
                item["pivot"] = name
                used.add(name)
                break
        out.append(item)
    missing = {r[0] for r in rules} - used
    if missing:
        raise SystemExit("timeline is missing key moments: %s" % ", ".join(sorted(missing)))
    return out


def video_seconds(path):
    import subprocess
    try:
        out = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path])
        return int(round(float(out)))
    except (OSError, subprocess.CalledProcessError, ValueError):
        return None


def build(out_docs):
    site = read_json("site", "site.json")
    ui = read_json("site", "ui.json")
    work = tempfile.mkdtemp(prefix="qassas-site-")
    try:
        case_dir = os.path.join(work, "case")
        lab.write_case(case_dir)
        files = {}
        for rel in SAMPLES:
            with open(os.path.join(case_dir, rel), "rb") as fh:
                files["labs/case-01/" + rel] = fh.read()
        with open(os.path.join(case_dir, "evidence", "laptop.img"), "rb") as fh:
            photo = [c for c in carve.carve_bytes(fh.read(), ["jpg"]) if c["offset"] == 131072][0]
        files["labs/case-01/carved/deleted_photo.jpg"] = photo["data"]
        zipped = make_zip(case_dir)
        files["labs/case-01.zip"] = zipped
        events = pivots(examine.examine(case_dir)["events"])
        questions = json.loads(files["labs/case-01/questions.json"])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    tools = load("tools")
    case = dict(questions)
    case["zipSha256"] = hashlib.sha256(zipped).hexdigest()
    case["zipMB"] = "%.1f" % (len(zipped) / 1e6)
    videos = {}
    for lang in ("ar", "en"):
        mp4 = "media/explainer/qassas-explainer-%s.mp4" % lang
        videos[lang] = {"src": mp4, "vtt": "media/explainer/qassas-explainer-%s.vtt" % lang,
                        "seconds": video_seconds(os.path.join(DOCS, mp4)) or 0}
    bundle = {
        "version": __version__,
        "ui": ui,
        "author": site["author"],
        "install": site["install"],
        "labs": site["labs"],
        "media": site["media"],
        "pivotText": site["pivots"],
        "videos": videos,
        "modules": load("curriculum")["modules"],
        "glossary": load("glossary"),
        "legal": load("legal"),
        "tools": tools,
        "case": case,
        "timeline": events,
        "signatures": load("signatures"),
        "areas": [{"name": {"en": en, "ar": ar}, "lat": lat, "lon": lon} for en, ar, lat, lon in geo.AREAS],
        "custodyText": EXPLAIN,
    }
    text = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    files["data/bundle.json"] = text.encode("utf-8")
    return files


def main():
    check = "--check" in sys.argv
    files = build(DOCS)
    stale = []
    for rel, data in sorted(files.items()):
        path = os.path.join(DOCS, rel)
        if check:
            try:
                with open(path, "rb") as fh:
                    if fh.read() != data:
                        stale.append(rel)
            except FileNotFoundError:
                stale.append(rel + " (missing)")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    if check:
        if stale:
            print("stale generated files, run scripts/build_site.py:\n  " + "\n  ".join(stale))
            sys.exit(1)
        print("site build is current (%d files)" % len(files))
    else:
        size = sum(len(d) for d in files.values())
        print("built %d files, %.1f MB" % (len(files), size / 1e6))


if __name__ == "__main__":
    main()
