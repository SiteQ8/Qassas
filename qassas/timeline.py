"""Merge events from every source into one timeline.

Each parser speaks its own time format: FILETIME in shortcuts, WebKit time in
Chromium, local syslog time in auth.log, epoch seconds in pcap, local time in
EXIF. The timeline converts all of them to UTC first, sorts them, and only
then shows them in the zone the reader asks for. Mixing zones is the single
most common timeline mistake.
"""

import csv
import io
import json
import os

from . import browser, custody, lnk, logs, metadata, pcap
from .timeutil import KUWAIT, UTC, iso, parse_iso


def event(time_utc, source, kind, description, artifact, **extra):
    ev = {"time_utc": time_utc, "source": source, "type": kind, "description": description, "artifact": artifact}
    ev.update({k: v for k, v in extra.items() if v is not None})
    return ev


def from_filesystem(root):
    """File system modified and changed times for every file (MACB style, M and C only)."""
    out = []
    for base, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.stat(full)
            from .timeutil import from_unix
            out.append(event(iso(from_unix(st.st_mtime)), "filesystem", "modified", "File content last modified", rel))
    return out


def from_browser(path, label):
    h = browser.read_history(path)
    out = []
    for v in h["visits"]:
        out.append(event(v["time_utc"], "browser", "visit", "%s (%s)" % (v["url"], v["transition"]), label, url=v["url"]))
    for d in h["downloads"]:
        out.append(event(d["time_utc"], "browser", "download", "Downloaded %s from %s" % (d["target_path"], d["tab_url"]), label,
                         url=d["tab_url"]))
    for s in h["searches"]:
        out.append(event(s["time_utc"], "browser", "search", "Searched for: %s" % s["term"], label))
    return out


def from_lnk(path, label):
    info = lnk.parse(path)
    target = info.get("local_base_path") or info.get("relative_path") or "?"
    out = []
    for key, kind in (("target_created_utc", "target_created"), ("target_modified_utc", "target_modified"),
                      ("target_accessed_utc", "target_accessed")):
        if info.get(key):
            out.append(event(info[key], "lnk", kind, "Shortcut records %s of %s" % (kind.replace("target_", ""), target), label))
    return out


def from_auth_log(path, label, year, tz=KUWAIT):
    with open(path, encoding="utf-8") as fh:
        evs = logs.parse_auth_log(fh.read(), year, tz)
    out = []
    for e in evs:
        desc = {"ssh_failed": "SSH login failed for %s from %s", "ssh_accepted": "SSH login accepted for %s from %s",
                "ssh_invalid_user": "SSH attempt for unknown user %s from %s"}.get(e["type"])
        text = desc % (e.get("user"), e.get("source_ip")) if desc else "%s %s" % (e["type"], e.get("command") or e.get("user") or "")
        out.append(event(e["time_utc"], "auth_log", e["type"], text.strip(), label, host=e.get("host"), ip=e.get("source_ip")))
    return out


def from_pcap(path, label):
    with open(path, "rb") as fh:
        res = pcap.analyse(fh.read())
    out = []
    for d in res["dns"]:
        out.append(event(d["time_utc"], "network", "dns_query", "%s asked for %s" % (d["client"], d["query"]), label, ip=d["client"]))
    for s in res["tls_sni"]:
        out.append(event(s["time_utc"], "network", "tls", "%s opened TLS to %s (%s)" % (s["client"], s["sni"], s["server"]), label))
    for h in res["http"]:
        out.append(event(h["time_utc"], "network", "http", "%s %s %s%s (%d bytes)" % (h["client"], h["method"], h["host"] or h["server"],
                                                                                     h["path"], h["bytes"]), label))
    return out


def from_photo(path, label):
    meta = metadata.extract(path)
    t = meta.get("datetime_original")
    if not t:
        return []
    dt = metadata.exif_time(t, meta.get("offset_time_original"))
    if dt is None:
        return []
    note = ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=KUWAIT)
        note = " (no zone in EXIF, Kuwait time assumed)"
    where = " at %s, %s" % (meta["gps"]["lat"], meta["gps"]["lon"]) if meta.get("gps") else ""
    return [event(iso(dt.astimezone(UTC)), "exif", "photo_taken", "Photo taken with %s %s%s%s" % (
        meta.get("make", "?"), meta.get("model", "?"), where, note), label)]


def from_pdf(path, label):
    meta = metadata.extract(path)
    out = []
    for key, kind in (("creationdate", "document_created"), ("moddate", "document_modified")):
        dt = metadata.pdf_date(meta.get(key))
        if dt:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=KUWAIT)
            out.append(event(iso(dt.astimezone(UTC)), "document", kind, "%s by %s" % (kind.replace("_", " "), meta.get("author", "?")), label))
    return out


def from_custody(path, label):
    return [event(e["time_utc"], "custody", e["action"], "%s %s by %s%s" % (e["item"], e["action"], e["by"],
                                                                             (" to " + e["to"]) if e.get("to") else ""), label)
            for e in custody.read(path)]


def sort(events):
    return sorted(events, key=lambda e: (parse_iso(e["time_utc"]), e["source"], e["artifact"]))


def localise(events, tz):
    out = []
    for e in events:
        e = dict(e)
        e["time"] = iso(parse_iso(e["time_utc"]), tz)
        out.append(e)
    return out


def to_csv(events):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["time", "time_utc", "source", "type", "description", "artifact"])
    for e in events:
        w.writerow([e.get("time", e["time_utc"]), e["time_utc"], e["source"], e["type"], e["description"], e["artifact"]])
    return buf.getvalue()


def to_jsonl(events):
    return "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events)
