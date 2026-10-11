"""The qassas command line.

Every command prints readable text by default and JSON with --json, so the
same tool serves a student reading output and a script chaining steps.
"""

import argparse
import json
import os
import sys

from . import (__version__, browser, carve, custody, examine, hashing, lab, lnk, logs, metadata, pcap,
               signatures, strings, timeline)
from .data_files import load
from .timeutil import KUWAIT, zone


def emit(obj, as_json):
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
        return True
    return False


def cmd_hash(a):
    out = []
    for p in a.paths:
        h = hashing.hash_file(p)
        h["path"] = p
        out.append(h)
    if not emit(out, a.json):
        for h in out:
            print("%s\n  size    %d\n  md5     %s\n  sha1    %s\n  sha256  %s" % (h["path"], h["size"], h["md5"], h["sha1"], h["sha256"]))


def cmd_manifest(a):
    if a.action == "create":
        m = hashing.make_manifest(a.root, case=a.case, examiner=a.examiner)
        dest = a.out or os.path.join(a.root, "manifest.json")
        hashing.write_manifest(m, dest)
        if a.sha256sum:
            with open(dest + ".sha256", "w", encoding="utf-8") as fh:
                fh.write(hashing.sha256sum_lines(m))
        print("wrote %s with %d files" % (dest, len(m["files"])))
    else:
        with open(a.manifest, encoding="utf-8") as fh:
            m = json.load(fh)
        r = hashing.verify_manifest(m, a.root)
        if not emit(r, a.json):
            print("ok %d, modified %d, missing %d, extra %d" % (len(r["ok"]), len(r["modified"]), len(r["missing"]), len(r["extra"])))
            for item in r["modified"]:
                print("  MODIFIED %s" % item["path"])
            for item in r["missing"]:
                print("  MISSING  %s" % item)
            for item in r["extra"]:
                print("  EXTRA    %s" % item)
            print("PASS" if r["passed"] else "FAIL")
        sys.exit(0 if r["passed"] else 1)


def cmd_custody(a):
    if a.action == "add":
        e = custody.append(a.log, action=a.what, item=a.item, by=a.by, to=a.to, location=a.location,
                           note=a.note, item_sha256=a.sha256)
        print("entry %d written, hash %s" % (e["seq"], e["hash"]))
        return
    entries = custody.read(a.log)
    if a.action == "show":
        if not emit(entries, a.json):
            for e in entries:
                print("#%-3d %s  %-11s %s  by %s%s" % (e["seq"], e["time_utc"], e["action"], e["item"], e["by"],
                                                     (" to " + e["to"]) if e.get("to") else ""))
        return
    problems = custody.verify(entries)
    if not emit(problems, a.json):
        if not problems:
            print("chain intact: %d entries" % len(entries))
        for p in problems:
            print("entry %s: %s / %s" % (p["seq"], custody.EXPLAIN[p["code"]]["en"], custody.EXPLAIN[p["code"]]["ar"]))
    sys.exit(1 if problems else 0)


def cmd_identify(a):
    out = []
    for p in a.paths:
        if os.path.isdir(p):
            out += signatures.scan(p)
        else:
            out.append(signatures.identify(p))
    if not emit(out, a.json):
        for v in out:
            mark = {"match": "  ", "mismatch": "!!", "unknown": "??"}[v["status"]]
            print("%s %-45s %-10s %s" % (mark, v.get("path", v["name"]), v["detected"] or "-", v["description"] or ""))
        bad = [v for v in out if v["status"] == "mismatch"]
        if bad:
            print("\n%d file(s) whose name does not match their content" % len(bad))


def cmd_carve(a):
    found = carve.carve(a.image, a.out, types=a.types.split(",") if a.types else None)
    if not emit(found, a.json):
        for f in found:
            print("%-4s offset %10d  size %8d  %s  %s" % (f["type"], f["offset"], f["size"], f["sha256"][:16], f.get("file", "")))
        print("%d file(s) carved" % len(found))


def cmd_meta(a):
    out = {p: metadata.extract(p) for p in a.paths}
    emit(out, True)


def cmd_strings(a):
    with open(a.path, "rb") as fh:
        data = fh.read()
    res = strings.scan(data, a.min)
    if a.json:
        emit(res if a.all else {k: v for k, v in res.items() if k != "strings"}, True)
        return
    rows = res["strings"] if a.all else res["arabic"]
    for s in rows:
        print("%10d %-8s %s" % (s["offset"], s["encoding"], s["text"]))
    for kind, vals in res["indicators"].items():
        print("[%s] %s" % (kind, ", ".join(vals)))


def cmd_browser(a):
    h = browser.read_history(a.path)
    if not emit(h, a.json):
        for v in h["visits"]:
            print("%s  %-8s %s" % (v["time_utc"], v["transition"], v["url"]))
        for d in h["downloads"]:
            print("DOWNLOAD %s  %s  <- %s" % (d["time_utc"], d["target_path"], d["tab_url"]))
        for s in h["searches"]:
            print("SEARCH   %s  %s" % (s["time_utc"], s["term"]))


def cmd_lnk(a):
    emit({p: lnk.parse(p) for p in a.paths}, True)


def cmd_logs(a):
    if a.path.endswith((".jsonl", ".json", ".csv")):
        evs = logs.parse_windows_export(a.path)
    else:
        with open(a.path, encoding="utf-8") as fh:
            evs = logs.parse_auth_log(fh.read(), a.year, zone(a.host_tz))
    found = logs.findings(evs, a.threshold)
    if not emit({"events": evs, "findings": found}, a.json):
        tz = zone(a.tz)
        from .timeutil import iso, parse_iso
        for e in evs:
            who = e.get("user") or ""
            extra = e.get("source_ip") or e.get("service") or e.get("process") or e.get("command") or ""
            print("%s  %-20s %-12s %s" % (iso(parse_iso(e["time_utc"]), tz), e["type"], who, extra))
        for f in found:
            print("FINDING [%s] %s %s" % (f["severity"], logs.FINDING_TEXT[f["code"]]["en"],
                                          {k: v for k, v in f.items() if k not in ("code", "severity")}))


def cmd_pcap(a):
    with open(a.path, "rb") as fh:
        res = pcap.analyse(fh.read())
    if not emit(res, a.json):
        print("%d packets, %d conversations" % (res["packets"], len(res["conversations"])))
        for c in res["conversations"][:10]:
            print("  %s -> %s %s/%s  %d pkts %d bytes" % (c["src"], c["dst"], c["proto"], c["dport"], c["packets"], c["bytes"]))
        seen = sorted({d["query"] for d in res["dns"]})
        print("DNS names: " + ", ".join(seen))
        print("TLS names: " + ", ".join(sorted({s["sni"] for s in res["tls_sni"]})))
        for h in res["http"]:
            print("HTTP %s %s %s%s (%d bytes, %s)" % (h["time_utc"], h["method"], h["host"], h["path"], h["bytes"], h["user_agent"]))
        for b in res["beacons"]:
            print("BEACON %s -> %s every %ss x%d (jitter %.3f) %s .. %s" % (
                b["client"], b["target"], b["interval_s"], b["count"], b["jitter_cv"], b["first_utc"], b["last_utc"]))


def cmd_timeline(a):
    res = examine.examine(a.case, a.year)
    events = timeline.localise(res["events"], zone(a.tz))
    if a.format == "csv":
        sys.stdout.write(timeline.to_csv(events))
    else:
        sys.stdout.write(timeline.to_jsonl(events))


def cmd_report(a):
    res = examine.examine(a.case, a.year)
    if a.json:
        emit(res, True)
        return
    text = examine.markdown(res, a.lang)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote " + a.out)
    else:
        sys.stdout.write(text)


def cmd_lab(a):
    if a.action == "list":
        for c in [load("case-01")]:
            print("%s  %s  %s" % (c["id"], c["title"]["en"], c["title"]["ar"]))
        return
    if a.action == "make":
        r = lab.write_case(a.out)
        print("case %s written to %s (%d evidence files)" % (r["case"], r["dir"], r["files"]))
        print("start with: qassas manifest verify %s/manifest.json --root %s/evidence" % (a.out, a.out))
        return
    with open(a.answers, encoding="utf-8") as fh:
        given = json.load(fh)
    res = lab.check(a.questions, given)
    score = sum(r["correct"] for r in res)
    if not emit({"score": score, "of": len(res), "results": res}, a.json):
        for r in res:
            print("%s  %s" % (r["id"], "correct" if r["correct"] else ("wrong" if r["answered"] else "not answered")))
        print("score %d / %d" % (score, len(res)))


def cmd_glossary(a):
    terms = load("glossary")
    q = (a.term or "").lower()
    hits = [t for t in terms if not q or q in t["term"]["en"].lower() or q in t["term"]["ar"] or q in t["id"]]
    if not emit(hits, a.json):
        for t in hits:
            print("%s / %s\n  %s\n  %s\n" % (t["term"]["en"], t["term"]["ar"], t["def"]["en"], t["def"]["ar"]))


def cmd_law(a):
    rows = load("legal")
    if a.country:
        rows = [r for r in rows if r["country"].lower() == a.country.lower()]
    if not emit(rows, a.json):
        for r in rows:
            title = r["title"]["ar"] if a.lang == "ar" else r["title"]["en"]
            summary = r["summary"]["ar"] if a.lang == "ar" else r["summary"]["en"]
            print("[%s %s] %s\n  %s\n  %s\n" % (r["country"], r["year"], title, summary, r["source"]["url"]))


def cmd_mcp(a):
    from . import mcp
    mcp.serve(a.root)


def build_parser():
    p = argparse.ArgumentParser(prog="qassas", description="Qassas digital forensics teaching toolkit")
    p.add_argument("--version", action="version", version="qassas " + __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_text):
        s = sub.add_parser(name, help=help_text)
        s.add_argument("--json", action="store_true", help="print JSON")
        s.set_defaults(fn=fn)
        return s

    s = add("hash", cmd_hash, "MD5, SHA-1 and SHA-256 of files")
    s.add_argument("paths", nargs="+")
    s = add("manifest", cmd_manifest, "create or verify an evidence manifest")
    s.add_argument("action", choices=["create", "verify"])
    s.add_argument("manifest", nargs="?", help="manifest.json to verify")
    s.add_argument("--root", required=True, help="evidence folder")
    s.add_argument("--case")
    s.add_argument("--examiner")
    s.add_argument("--out")
    s.add_argument("--sha256sum", action="store_true", help="also write a sha256sum -c compatible file")
    s = add("custody", cmd_custody, "append to, show or verify a chain of custody log")
    s.add_argument("action", choices=["add", "show", "verify"])
    s.add_argument("log")
    s.add_argument("--what", choices=custody.ACTIONS)
    s.add_argument("--item")
    s.add_argument("--by")
    s.add_argument("--to")
    s.add_argument("--location")
    s.add_argument("--note")
    s.add_argument("--sha256")
    s = add("identify", cmd_identify, "identify files by signature and flag renamed ones")
    s.add_argument("paths", nargs="+")
    s.add_argument("--recursive", action="store_true", help="accepted for readability, folders are always scanned")
    s = add("carve", cmd_carve, "carve JPEG, PNG, GIF, PDF and ZIP files from raw data")
    s.add_argument("image")
    s.add_argument("out", nargs="?")
    s.add_argument("--types", help="comma separated: jpg,png,gif,pdf,zip")
    s = add("meta", cmd_meta, "EXIF, PNG text, PDF and Office metadata")
    s.add_argument("paths", nargs="+")
    s = add("strings", cmd_strings, "ASCII, UTF-8 and UTF-16 strings with Arabic and indicators")
    s.add_argument("path")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--all", action="store_true", help="print every string, not only Arabic")
    s = add("browser", cmd_browser, "Chromium or Firefox history")
    s.add_argument("path")
    s = add("lnk", cmd_lnk, "Windows shortcut files")
    s.add_argument("paths", nargs="+")
    s = add("logs", cmd_logs, "Linux auth.log or exported Windows security events")
    s.add_argument("path")
    s.add_argument("--year", type=int, default=2026, help="syslog lines carry no year")
    s.add_argument("--host-tz", default="kuwait", help="zone the host wrote its log in: kuwait or utc")
    s.add_argument("--tz", default="kuwait", help="zone to display: kuwait or utc")
    s.add_argument("--threshold", type=int, default=5)
    s = add("pcap", cmd_pcap, "DNS, TLS names, HTTP and beaconing from a pcap")
    s.add_argument("path")
    s = add("timeline", cmd_timeline, "merge every source in a case into one timeline")
    s.add_argument("case")
    s.add_argument("--tz", default="kuwait")
    s.add_argument("--year", type=int, default=2026)
    s.add_argument("--format", choices=["csv", "jsonl"], default="csv")
    s = add("report", cmd_report, "examine a case folder and write a report")
    s.add_argument("case")
    s.add_argument("--lang", choices=["en", "ar"], default="en")
    s.add_argument("--year", type=int, default=2026)
    s.add_argument("--out")
    s = add("lab", cmd_lab, "make the practice case or check your answers")
    s.add_argument("action", choices=["list", "make", "check"])
    s.add_argument("--out", default="qassas-case-01")
    s.add_argument("--questions", default="qassas-case-01/questions.json")
    s.add_argument("--answers", default="answers.json")
    s = add("glossary", cmd_glossary, "look up a term in English or Arabic")
    s.add_argument("term", nargs="?")
    s = add("law", cmd_law, "Kuwait and GCC laws and standards for digital evidence")
    s.add_argument("--country", help="KW, SA, AE, QA, BH, OM or INTL")
    s.add_argument("--lang", choices=["en", "ar"], default="en")
    s = add("mcp", cmd_mcp, "run the MCP server on stdio")
    s.add_argument("--root", default=".", help="the only folder the server may read")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (FileNotFoundError, ValueError) as err:
        print("qassas: %s" % err, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
