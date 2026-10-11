"""A Model Context Protocol server for Qassas, over stdio.

It lets an AI assistant use the toolkit the way a student does: identify,
hash, read metadata, parse artifacts, verify custody and look up lessons,
terms and laws. Every tool is read only, and every path is confined to the
folder given with --root, so the assistant cannot read anything else.

Run:  qassas mcp --root ./qassas-case-01
"""

import json
import os
import sys

from . import (__version__, browser, custody, examine, hashing, lnk, logs, metadata, pcap, signatures,
               strings)
from .data_files import load

PROTOCOL = "2025-06-18"


def _schema(props, required=()):
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


PATH = {"type": "string", "description": "Path relative to the server root"}
TOOLS = [
    ("identify_file", "Identify a file or every file in a folder by its signature and flag names that do not match content.",
     _schema({"path": PATH}, ["path"])),
    ("hash_file", "MD5, SHA-1 and SHA-256 of a file.", _schema({"path": PATH}, ["path"])),
    ("extract_metadata", "EXIF with GPS and nearest Kuwaiti area, PNG text, PDF info and revisions, Office properties.",
     _schema({"path": PATH}, ["path"])),
    ("extract_strings", "Arabic text and indicators (URLs, emails, IPv4, Kuwaiti mobiles and IBANs) from any file.",
     _schema({"path": PATH, "min_length": {"type": "integer", "minimum": 3, "default": 6}}, ["path"])),
    ("read_browser_history", "Visits, downloads and searches from a Chromium History or Firefox places.sqlite file.",
     _schema({"path": PATH}, ["path"])),
    ("parse_shortcut", "Target path, times and volume from a Windows LNK file.", _schema({"path": PATH}, ["path"])),
    ("analyse_logs", "Events and findings from a Linux auth.log or exported Windows security events.",
     _schema({"path": PATH, "year": {"type": "integer", "default": 2026}}, ["path"])),
    ("analyse_pcap", "DNS, TLS server names, HTTP requests, conversations and beaconing from a pcap.",
     _schema({"path": PATH}, ["path"])),
    ("verify_custody", "Verify a hash chained custody log and explain any break in English and Arabic.",
     _schema({"path": PATH}, ["path"])),
    ("verify_manifest", "Check an evidence folder against its manifest.json.",
     _schema({"manifest": PATH, "root": PATH}, ["manifest", "root"])),
    ("examine_case", "Run the full examination of a case folder and return a report in English or Arabic.",
     _schema({"path": PATH, "lang": {"type": "string", "enum": ["en", "ar"], "default": "en"}}, ["path"])),
    ("glossary", "Look up digital forensics terms in English or Arabic.", _schema({"term": {"type": "string"}})),
    ("law", "Kuwait and GCC laws and standards on cybercrime, electronic evidence and breach reporting.",
     _schema({"country": {"type": "string", "enum": ["KW", "SA", "AE", "QA", "BH", "OM", "INTL"]},
              "query": {"type": "string"}})),
    ("lesson", "The Qassas lesson for a module, with objectives and steps, in both languages.",
     _schema({"module": {"type": "string", "description": "Module id, or empty to list modules"}})),
]


class Server:
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def path(self, rel):
        full = os.path.realpath(os.path.join(self.root, rel))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise ValueError("path is outside the server root")
        if not os.path.exists(full):
            raise ValueError("no such file: %s" % rel)
        return full

    def call(self, name, args):
        p = self.path
        if name == "identify_file":
            full = p(args["path"])
            return signatures.scan(full) if os.path.isdir(full) else signatures.identify(full)
        if name == "hash_file":
            return hashing.hash_file(p(args["path"]))
        if name == "extract_metadata":
            return metadata.extract(p(args["path"]))
        if name == "extract_strings":
            with open(p(args["path"]), "rb") as fh:
                res = strings.scan(fh.read(), int(args.get("min_length", 6)))
            res.pop("strings")
            return res
        if name == "read_browser_history":
            return browser.read_history(p(args["path"]))
        if name == "parse_shortcut":
            return lnk.parse(p(args["path"]))
        if name == "analyse_logs":
            full = p(args["path"])
            if full.endswith((".jsonl", ".json", ".csv")):
                evs = logs.parse_windows_export(full)
            else:
                with open(full, encoding="utf-8") as fh:
                    evs = logs.parse_auth_log(fh.read(), int(args.get("year", 2026)))
            return {"events": evs, "findings": logs.findings(evs)}
        if name == "analyse_pcap":
            with open(p(args["path"]), "rb") as fh:
                res = pcap.analyse(fh.read())
            res["conversations"] = res["conversations"][:25]
            return res
        if name == "verify_custody":
            probs = custody.verify(custody.read(p(args["path"])))
            for x in probs:
                x["explain"] = custody.EXPLAIN[x["code"]]
            return {"intact": not probs, "problems": probs}
        if name == "verify_manifest":
            with open(p(args["manifest"]), encoding="utf-8") as fh:
                return hashing.verify_manifest(json.load(fh), p(args["root"]))
        if name == "examine_case":
            return examine.markdown(examine.examine(p(args["path"])), args.get("lang", "en"))
        if name == "glossary":
            q = (args.get("term") or "").lower()
            return [t for t in load("glossary") if not q or q in t["term"]["en"].lower() or q in t["term"]["ar"]]
        if name == "law":
            rows = load("legal")
            if args.get("country"):
                rows = [r for r in rows if r["country"] == args["country"]]
            q = (args.get("query") or "").lower()
            if q:
                rows = [r for r in rows if q in json.dumps(r, ensure_ascii=False).lower()]
            return rows
        if name == "lesson":
            mods = load("curriculum")["modules"]
            if not args.get("module"):
                return [{"id": m["id"], "title": m["title"]} for m in mods]
            for m in mods:
                if m["id"] == args["module"]:
                    return m
            raise ValueError("no module %r" % args["module"])
        raise ValueError("unknown tool %r" % name)

    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return None  # a notification needs no reply
        try:
            if method == "initialize":
                result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "qassas", "version": __version__},
                          "instructions": "Read only digital forensics tools confined to %s. Times are UTC unless a tool says otherwise." % self.root}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [{"name": n, "description": d, "inputSchema": s,
                                     "annotations": {"readOnlyHint": True, "openWorldHint": False}} for n, d, s in TOOLS]}
            elif method == "tools/call":
                params = msg.get("params", {})
                try:
                    value = self.call(params.get("name"), params.get("arguments") or {})
                    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=1, default=str)
                    result = {"content": [{"type": "text", "text": text}], "isError": False}
                except (ValueError, KeyError, OSError) as err:
                    result = {"content": [{"type": "text", "text": "error: %s" % err}], "isError": True}
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: %s" % method}}
            return {"jsonrpc": "2.0", "id": mid, "result": result}
        except Exception as err:  # never let one bad request kill the session
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(err)}}


def serve(root=".", stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    server = Server(root)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = server.handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
