"""Behaviour tests for every toolkit module, mostly against the generated practice case."""

import hashlib
import io
import json
import os
import random
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from qassas import (browser, carve, cli, custody, examine, geo, hashing, lab, lab_assets, lnk, logs,  # noqa: E402
                    mcp, metadata, pcap, signatures, strings, timeline)
from qassas.timeutil import KUWAIT, UTC, from_filetime, from_webkit, iso, to_filetime, to_webkit  # noqa: E402

TMP = None
CASE = None
EV = None


def setUpModule():
    global TMP, CASE, EV
    TMP = tempfile.mkdtemp(prefix="qassas-test-")
    CASE = os.path.join(TMP, "case")
    lab.write_case(CASE)
    EV = os.path.join(CASE, "evidence")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


class TimeTests(unittest.TestCase):
    def test_webkit_and_filetime_round_trip(self):
        dt = datetime(2026, 10, 4, 5, 42, 9, tzinfo=UTC)
        self.assertEqual(from_webkit(to_webkit(dt)), dt)
        self.assertEqual(from_filetime(to_filetime(dt)), dt)

    def test_kuwait_is_plus_three_all_year(self):
        for month in (1, 4, 7, 10):
            dt = datetime(2026, month, 1, 6, 0, tzinfo=UTC)
            self.assertTrue(iso(dt, KUWAIT).endswith("09:00:00+03:00"))


class HashingTests(unittest.TestCase):
    def test_known_vectors(self):
        h = hashing.hash_bytes(b"abc")
        self.assertEqual(h["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(h["md5"], "900150983cd24fb0d6963f7d28e17f72")

    def test_manifest_detects_change_missing_and_extra(self):
        d = tempfile.mkdtemp(dir=TMP)
        for name, data in (("a.bin", b"one"), ("b.bin", b"two")):
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(data)
        m = hashing.make_manifest(d)
        self.assertTrue(hashing.verify_manifest(m, d)["passed"])
        with open(os.path.join(d, "a.bin"), "ab") as fh:
            fh.write(b"!")
        os.remove(os.path.join(d, "b.bin"))
        with open(os.path.join(d, "c.bin"), "wb") as fh:
            fh.write(b"new")
        r = hashing.verify_manifest(m, d)
        self.assertFalse(r["passed"])
        self.assertEqual([x["path"] for x in r["modified"]], ["a.bin"])
        self.assertEqual(r["missing"], ["b.bin"])
        self.assertEqual(r["extra"], ["c.bin"])
        self.assertIn("a.bin", hashing.sha256sum_lines(m))

    def test_case_manifest_passes(self):
        with open(os.path.join(CASE, "manifest.json"), encoding="utf-8") as fh:
            self.assertTrue(hashing.verify_manifest(json.load(fh), EV)["passed"])


class CustodyTests(unittest.TestCase):
    def entries(self):
        return custody.read(os.path.join(CASE, "custody", "custody.jsonl"))

    def test_intact_chain(self):
        self.assertEqual(custody.verify(self.entries()), [])

    def test_edit_is_located(self):
        e = self.entries()
        e[2]["note"] = "edited"
        self.assertEqual([(p["seq"], p["code"]) for p in custody.verify(e)], [(3, "entry_altered")])

    def test_deletion_is_located(self):
        e = self.entries()
        del e[3]
        codes = {(p["seq"], p["code"]) for p in custody.verify(e)}
        self.assertIn((5, "broken_link"), codes)
        self.assertIn((5, "sequence"), codes)

    def test_time_reversal_and_item_hash_change(self):
        entries = []
        entries.append(custody.make_entry(entries, "seized", "X", "A", time_utc="2026-10-04T10:00:00+00:00", item_sha256="aa"))
        entries.append(custody.make_entry(entries, "imaged", "X", "A", time_utc="2026-10-04T09:00:00+00:00", item_sha256="bb"))
        codes = {p["code"] for p in custody.verify(entries)}
        self.assertEqual(codes, {"time_reversed", "item_hash_changed"})

    def test_archive_copy_alteration(self):
        probs = custody.verify(custody.read(os.path.join(CASE, "custody", "custody_archive_copy.jsonl")))
        self.assertEqual([(p["seq"], p["code"]) for p in probs], [(5, "entry_altered")])

    def test_append_writes_jsonl(self):
        path = os.path.join(TMP, "c.jsonl")
        custody.append(path, action="seized", item="Phone", by="R1")
        custody.append(path, action="sealed", item="Phone", by="R1", note="seal 9")
        self.assertEqual(custody.verify(custody.read(path)), [])
        with self.assertRaises(ValueError):
            custody.append(path, action="lost", item="Phone", by="R1")

    def test_every_code_is_explained_in_both_languages(self):
        for code, text in custody.EXPLAIN.items():
            self.assertTrue(text["en"] and text["ar"], code)


class SignatureTests(unittest.TestCase):
    def test_every_signature_matches_its_own_bytes(self):
        for sig in signatures.SIGNATURES:
            if "zip_member" in sig:
                continue
            data = bytearray(sig["offset"] + 64)
            data[sig["offset"]:sig["offset"] + len(sig["magic"])] = sig["magic"]
            if "also" in sig:
                o = sig["also"]["offset"]
                data[o:o + len(sig["also_magic"])] = sig["also_magic"]
            got = signatures.match(bytes(data))
            self.assertIsNotNone(got, sig["id"])
            self.assertEqual(got["magic"][:len(sig["magic"])], sig["magic"], sig["id"])

    def test_office_and_apk_beat_plain_zip(self):
        for member, expected in (("[Content_Types].xml", "ooxml"), ("AndroidManifest.xml", "apk"), ("x.txt", "zip")):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr(member, "x")
            self.assertEqual(signatures.identify_bytes(buf.getvalue(), "f.zip")["detected"], expected)

    def test_renamed_archive_is_flagged(self):
        v = signatures.identify(os.path.join(EV, "Documents", "invoice_0921.jpg"))
        self.assertEqual((v["detected"], v["status"]), ("zip", "mismatch"))
        statuses = {r["path"]: r["status"] for r in signatures.scan(EV)}
        self.assertEqual([p for p, s in statuses.items() if s == "mismatch"], ["Documents/invoice_0921.jpg"])

    def test_unknown(self):
        self.assertEqual(signatures.identify_bytes(b"hello there", "a.txt")["status"], "unknown")


class CarveTests(unittest.TestCase):
    def test_case_image(self):
        found = carve.carve(os.path.join(EV, "laptop.img"))
        self.assertEqual([(f["type"], f["offset"]) for f in found],
                         [("jpg", 131072), ("zip", 420000), ("jpg", 700001), ("pdf", 1049353), ("png", 1600000)])
        pdf = read(os.path.join(EV, "Documents", "Tender_2026_Final.pdf"))
        self.assertEqual([f["sha256"] for f in found if f["type"] == "pdf"], [hashlib.sha256(pdf).hexdigest()])

    def test_embedded_thumbnail_does_not_cut_the_photo(self):
        thumb = lab_assets.DUNE
        seg = b"\xff\xe2" + struct.pack(">H", len(thumb) + 2) + thumb
        photo = lab_assets.WHITEBOARD[:2] + seg + lab_assets.WHITEBOARD[2:]
        blob = os.urandom(300) + photo + os.urandom(300)
        jpgs = [f for f in carve.carve_bytes(blob, ["jpg"])]
        self.assertEqual(len(jpgs), 1)
        self.assertEqual(jpgs[0]["data"], photo)

    def test_writes_files(self):
        out = os.path.join(TMP, "carved")
        found = carve.carve(os.path.join(EV, "laptop.img"), out)
        for f in found:
            self.assertEqual(hashlib.sha256(read(os.path.join(out, f["file"]))).hexdigest(), f["sha256"])


class MetadataTests(unittest.TestCase):
    def test_exif_gps_and_area(self):
        m = metadata.extract(os.path.join(TMP, "carved", "carved_001_at_131072.jpg")) if os.path.exists(
            os.path.join(TMP, "carved", "carved_001_at_131072.jpg")) else None
        if m is None:
            data = read(os.path.join(EV, "laptop.img"))[131072:131072 + 4000]
            m = metadata.jpeg_exif(data)
        self.assertEqual(m["gps"]["nearest_area"]["en"], "Salmiya")
        self.assertEqual(m["datetime_original"], "2026:10:03 19:12:40")
        dt = metadata.exif_time(m["datetime_original"], m["offset_time_original"])
        self.assertEqual(iso(dt, UTC), "2026-10-03T16:12:40+00:00")

    def test_pdf_revisions_and_dates(self):
        m = metadata.extract(os.path.join(EV, "Documents", "Tender_2026_Final.pdf"))
        self.assertEqual((m["author"], m["revisions"], m["version"]), ("Fahad", 2, "1.4"))
        self.assertEqual(iso(metadata.pdf_date(m["moddate"]), UTC), "2026-10-04T05:59:00+00:00")

    def test_png_text(self):
        data = read(os.path.join(EV, "laptop.img"))[1600000:1600193]
        m = metadata.png_text(data)
        self.assertEqual(m["Software"], "Qassas Lab Capture")
        self.assertEqual(m["tIME"], "2026-10-04T05:51:30Z")

    def test_ooxml_core(self):
        buf = io.BytesIO()
        core = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                '<dc:creator>Noura</dc:creator><cp:lastModifiedBy>Yousef</cp:lastModifiedBy>'
                '<dcterms:created>2026-10-01T08:00:00Z</dcterms:created></cp:coreProperties>')
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("docProps/core.xml", core)
        m = metadata.ooxml_core(io.BytesIO(buf.getvalue()))
        self.assertEqual((m["creator"], m["last_modified_by"]), ("Noura", "Yousef"))

    def test_geo(self):
        self.assertEqual(geo.nearest(29.3375, 47.6581)["en"], "Jahra")
        self.assertIsNone(geo.nearest(24.7136, 46.6753))


class StringsTests(unittest.TestCase):
    def test_arabic_in_both_encodings(self):
        res = strings.scan(read(os.path.join(EV, "laptop.img")), 6)
        texts = {(a["encoding"], a["text"]) for a in res["arabic"]}
        self.assertIn(("utf16le", "أرسل لي ملف المناقصة قبل الساعة 9 وامسح الرسالة بعدها"), texts)
        self.assertIn(("utf8", "مناقصة دار السنبوك 2026"), texts)
        self.assertEqual(len(texts), 2)
        ind = res["indicators"]
        self.assertEqual(ind["kw_iban"], ["KW00QSAS0000000000000000000000"])
        self.assertEqual(ind["kw_mobile"], ["+965 5000 0000"])

    def test_random_bytes_give_no_arabic(self):
        rng = random.Random(7)
        self.assertEqual(strings.scan(rng.randbytes(1 << 20), 6)["arabic"], [])


class BrowserTests(unittest.TestCase):
    def test_history_and_original_untouched(self):
        path = os.path.join(EV, "Browser", "History")
        before = hashlib.sha256(read(path)).hexdigest()
        h = browser.read_history(path)
        self.assertEqual(hashlib.sha256(read(path)).hexdigest(), before)
        self.assertEqual(h["browser"], "chromium")
        urls = [v["url"] for v in h["visits"]]
        self.assertIn("https://dar-alsanbouk-login.example/sso/reset", urls)
        self.assertEqual(h["downloads"][0]["referrer"], "https://dar-alsanbouk-login.example/sso/done")
        self.assertEqual(h["searches"][0]["term"], "مناقصة")
        self.assertEqual(h["visits"][2]["time_utc"], "2026-10-04T05:42:09+00:00")

    def test_firefox(self):
        path = os.path.join(TMP, "places.sqlite")
        con = sqlite3.connect(path)
        con.executescript("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT);"
                          "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);"
                          "INSERT INTO moz_places VALUES (1, 'https://example.kw/', 'KW');"
                          "INSERT INTO moz_historyvisits VALUES (1, 1, 1791100000000000, 1);")
        con.commit()
        con.close()
        h = browser.read_history(path)
        self.assertEqual((h["browser"], h["visits"][0]["url"]), ("firefox", "https://example.kw/"))


class LnkTests(unittest.TestCase):
    def test_case_shortcut(self):
        info = lnk.parse(os.path.join(EV, "Recent", "Tender_Update.lnk"))
        self.assertEqual(info["local_base_path"], lab.LNK_TARGET)
        self.assertEqual(info["drive_type"], "fixed")
        self.assertEqual(info["target_accessed_utc"], "2026-10-04T05:46:09+00:00")

    def test_rejects_other_files(self):
        with self.assertRaises(ValueError):
            lnk.parse_bytes(b"\x00" * 100)


class LogTests(unittest.TestCase):
    def test_auth_log_findings(self):
        evs = logs.parse_auth_log(read(os.path.join(EV, "Logs", "srv-files_auth.log")).decode(), 2026)
        f = {x["code"]: x for x in logs.findings(evs)}
        self.assertEqual(f["guess_then_success"]["time_utc"], "2026-10-04T06:27:03+00:00")
        self.assertEqual(f["guess_then_success"]["user"], "fahad")
        self.assertEqual(f["password_guessing"]["source_ip"], "203.0.113.45")

    def test_windows_export_json_and_csv(self):
        evs = logs.parse_windows_export(os.path.join(EV, "Logs", "LAPTOP-FHD01_security.jsonl"))
        self.assertIn(("service_installed", "SanboukUpdater"), [(e["type"], e.get("service")) for e in evs])
        self.assertEqual([f["code"] for f in logs.findings(evs)], ["log_cleared"])
        path = os.path.join(TMP, "sec.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("TimeCreated,Id,Computer,TargetUserName,IpAddress,LogonType\n")
            for i in range(6):
                fh.write("2026-10-04T06:0%d:00Z,4625,PC1,admin,203.0.113.9,3\n" % i)
            fh.write("2026-10-04T06:07:00Z,4624,PC1,admin,203.0.113.9,3\n")
        f = logs.findings(logs.parse_windows_export(path))
        self.assertIn("guess_then_success", [x["code"] for x in f])

    def test_every_finding_has_text(self):
        for code in ("password_guessing", "guess_then_success", "log_cleared", "risky_sudo"):
            self.assertTrue(logs.FINDING_TEXT[code]["ar"])


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.res = pcap.analyse(read(os.path.join(EV, "Network", "capture.pcap")))

    def test_beacons(self):
        b = {x["kind"]: x for x in self.res["beacons"]}
        self.assertEqual(set(b), {"dns", "tcp"})
        self.assertEqual(round(b["dns"]["interval_s"]), 60)
        self.assertEqual(b["dns"]["count"], 43)
        self.assertEqual(b["tcp"]["target"], "198.51.100.23:443")

    def test_exfil_and_names(self):
        self.assertEqual([(h["method"], h["host"], h["user_agent"]) for h in self.res["http"]],
                         [("POST", "updates.sanbouk-cdn.example", "SanboukUpdater/1.0")])
        self.assertIn("dar-alsanbouk-login.example", {s["sni"] for s in self.res["tls_sni"]})
        self.assertIn("updates.sanbouk-cdn.example", {d["query"] for d in self.res["dns"]})

    def test_formats(self):
        data = read(os.path.join(EV, "Network", "capture.pcap"))
        with self.assertRaises(ValueError):
            pcap.analyse(b"\x0a\x0d\x0d\x0a" + data[4:])
        with self.assertRaises(ValueError):
            pcap.analyse(b"nope" * 10)


class TimelineTests(unittest.TestCase):
    def test_sorted_in_utc_and_shown_in_kuwait(self):
        res = examine.examine(CASE)
        times = [e["time_utc"] for e in res["events"]]
        self.assertEqual(times, sorted(times, key=lambda t: datetime.fromisoformat(t)))
        local = timeline.localise(res["events"], KUWAIT)
        self.assertTrue(all(e["time"].endswith("+03:00") for e in local))
        csv_text = timeline.to_csv(local)
        self.assertTrue(csv_text.startswith("time,time_utc,source"))
        sources = {e["source"] for e in res["events"]}
        self.assertTrue({"browser", "lnk", "network", "auth_log", "windows", "exif", "document", "custody"} <= sources)


class LabTests(unittest.TestCase):
    def test_deterministic(self):
        other = os.path.join(TMP, "again")
        lab.write_case(other)
        for base, _dirs, files in os.walk(CASE):
            for name in files:
                a = os.path.join(base, name)
                b = os.path.join(other, os.path.relpath(a, CASE))
                self.assertEqual(read(a), read(b), os.path.relpath(a, CASE))

    def test_answer_key(self):
        q = os.path.join(CASE, "questions.json")
        key = {"q01": hashing.hash_file(os.path.join(EV, "laptop.img"))["sha256"], "q02": "invoice_0921.jpg",
               "q03": "Salmiya", "q04": "dar-alsanbouk-login.example", "q05": "9:27", "q06": "60", "q07": "5",
               "q08": "2", "q09": "c:/users/fahad/downloads/tender_update/update.exe", "q10": "2", "q11": "sanboukupdater",
               "q12": "43"}
        self.assertTrue(all(r["correct"] for r in lab.check(q, key)))
        self.assertFalse(lab.check(q, {"q03": "Jahra"})[2]["correct"])

    def test_tools_recover_every_answer(self):
        """Each question must be answerable with the toolkit itself."""
        res = examine.examine(CASE)
        keys = {f["key"] for f in res["findings"]}
        self.assertTrue({"gps", "beacon", "upload", "pdf_rev", "lnk", "download", "log_guess_then_success"} <= keys)
        gps = [f for f in res["findings"] if f["key"] == "gps"][0]
        self.assertEqual(gps["args"][0]["en"], "Salmiya")
        carved_jpgs = [f for f in res["files"] if f.get("status") == "carved" and f["detected"] == "jpg"]
        self.assertEqual(len(carved_jpgs), 2)


class ReportTests(unittest.TestCase):
    def test_reports_in_both_languages(self):
        res = examine.examine(CASE)
        for lang in ("en", "ar"):
            text = examine.markdown(res, lang)
            self.assertNotIn("None", text)
            self.assertNotIn("null", text)
            self.assertIn("invoice_0921.jpg", text)
        self.assertTrue(examine.markdown(res, "ar").startswith('<div dir="rtl">'))


class McpTests(unittest.TestCase):
    def rpc(self, server, method, params=None, mid=1):
        return server.handle({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})

    def test_protocol(self):
        s = mcp.Server(CASE)
        init = self.rpc(s, "initialize", {"protocolVersion": mcp.PROTOCOL})
        self.assertEqual(init["result"]["serverInfo"]["name"], "qassas")
        self.assertIsNone(s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = self.rpc(s, "tools/list")["result"]["tools"]
        self.assertEqual(len(tools), len(mcp.TOOLS))
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))
        self.assertEqual(self.rpc(s, "nope")["error"]["code"], -32601)

    def test_every_tool_runs(self):
        s = mcp.Server(CASE)
        calls = {
            "identify_file": {"path": "evidence"}, "hash_file": {"path": "evidence/laptop.img"},
            "extract_metadata": {"path": "evidence/Pictures/IMG_2038.jpg"}, "extract_strings": {"path": "evidence/laptop.img"},
            "read_browser_history": {"path": "evidence/Browser/History"}, "parse_shortcut": {"path": "evidence/Recent/Tender_Update.lnk"},
            "analyse_logs": {"path": "evidence/Logs/srv-files_auth.log"}, "analyse_pcap": {"path": "evidence/Network/capture.pcap"},
            "verify_custody": {"path": "custody/custody_archive_copy.jsonl"}, "verify_manifest": {"manifest": "manifest.json", "root": "evidence"},
            "examine_case": {"path": ".", "lang": "ar"}, "glossary": {"term": "carving"}, "law": {"country": "KW"},
            "lesson": {"module": "custody"},
        }
        self.assertEqual(set(calls), {t[0] for t in mcp.TOOLS})
        for name, args in calls.items():
            r = self.rpc(s, "tools/call", {"name": name, "arguments": args})["result"]
            self.assertFalse(r["isError"], (name, r["content"][0]["text"][:200]))

    def test_paths_are_confined(self):
        s = mcp.Server(EV)
        for bad in ("../manifest.json", "/etc/passwd", "Logs/../../questions.json"):
            r = self.rpc(s, "tools/call", {"name": "hash_file", "arguments": {"path": bad}})["result"]
            self.assertTrue(r["isError"], bad)

    def test_stdio(self):
        out = io.StringIO()
        lines = "\n".join(json.dumps(m) for m in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})) + "\nnot json\n"
        mcp.serve(CASE, io.StringIO(lines), out)
        replies = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([r.get("id") for r in replies], [1, 2, None])


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                cli.main(list(args))
            except SystemExit as e:
                if e.code not in (0, None):
                    raise
        return buf.getvalue()

    def test_commands(self):
        self.assertIn("sha256", self.run_cli("hash", os.path.join(EV, "laptop.img")))
        self.assertIn("!!", self.run_cli("identify", EV))
        self.assertIn("BEACON", self.run_cli("pcap", os.path.join(EV, "Network", "capture.pcap")))
        self.assertIn("chain intact", self.run_cli("custody", "verify", os.path.join(CASE, "custody", "custody.jsonl")))
        self.assertIn("PASS", self.run_cli("manifest", "verify", os.path.join(CASE, "manifest.json"), "--root", EV))
        self.assertIn("نحت الملفات", self.run_cli("glossary", "carving"))
        self.assertIn("time,time_utc", self.run_cli("timeline", CASE))
        data = json.loads(self.run_cli("law", "--country", "OM", "--json"))
        self.assertEqual({r["country"] for r in data}, {"OM"})


if __name__ == "__main__":
    unittest.main()
