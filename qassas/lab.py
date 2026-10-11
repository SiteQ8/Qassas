"""Generate the synthetic evidence for the Qassas practice case.

Case QS-2026-001, Dar Al Sanbouk: a fictional trading company in Sharq,
Kuwait City, loses a tender document after a phishing email. Every person,
company, domain and address in it is invented. Domains end in .example and
IP addresses come from the ranges reserved for documentation (RFC 5737), so
nothing here points at a real system.

The generator is deterministic: the same version always writes the same bytes
(except SQLite files, whose layout can vary between SQLite versions), so a
class can compare hashes and an instructor can grade answers by hash.
"""

import hashlib
import json
import os
import random
import struct
import unicodedata
import zipfile
import zlib
from datetime import datetime, timedelta

from . import custody, hashing, lab_assets, lnk, pcap
from .timeutil import KUWAIT, UTC, iso, to_webkit

CASE_ID = "case-01"
CASE_REF = "QS-2026-001"
SEED = 20261004

ORG_DOMAIN = "dar-alsanbouk.example"
PHISH_DOMAIN = "dar-alsanbouk-login.example"
C2_DOMAIN = "updates.sanbouk-cdn.example"
FILES_DOMAIN = "files.sanbouk-cdn.example"
LAPTOP_IP, DNS_IP, FILESRV_IP = "10.10.20.15", "10.10.20.1", "10.10.20.5"
C2_IP, PHISH_IP, ATTACKER_IP, PORTAL_IP = "198.51.100.23", "198.51.100.77", "203.0.113.45", "192.0.2.10"
SALMIYA = (29.3346, 48.0715)
LNK_TARGET = r"C:\Users\fahad\Downloads\Tender_Update\update.exe"
SERVICE = "SanboukUpdater"


def kwt(day, h, m, s=0):
    """A Kuwait local time on 2026-10-<day>, returned in UTC."""
    return datetime(2026, 10, day, h, m, s, tzinfo=KUWAIT).astimezone(UTC)


# ---------------------------------------------------------------- photos

def _rational(value):
    return struct.pack("<II", int(round(value * 10000)), 10000)


def _dms(deg):
    d = int(deg)
    m_full = (deg - d) * 60
    m = int(m_full)
    s = (m_full - m) * 60
    return struct.pack("<II", d, 1) + struct.pack("<II", m, 1) + _rational(s)


def exif_block(make, model, taken, offset="+03:00", gps=None):
    """Build an Exif APP1 segment (little endian TIFF) by hand."""
    entries0, entries_exif, entries_gps = [], [], []

    def ascii_tag(store, tag, text):
        raw = text.encode("ascii") + b"\x00"
        store.append((tag, 2, len(raw), raw))

    ascii_tag(entries0, 0x010F, make)
    ascii_tag(entries0, 0x0110, model)
    ascii_tag(entries0, 0x0132, taken)
    ascii_tag(entries_exif, 0x9003, taken)
    ascii_tag(entries_exif, 0x9011, offset)
    if gps:
        lat, lon = gps
        entries_gps.append((1, 2, 2, b"N\x00"))
        entries_gps.append((2, 5, 3, _dms(lat)))
        entries_gps.append((3, 2, 2, b"E\x00"))
        entries_gps.append((4, 5, 3, _dms(lon)))
        ascii_tag(entries_gps, 0x1D, taken[:10])

    def ifd_size(entries):
        return 2 + 12 * len(entries) + 4 + sum(len(raw) for *_x, raw in entries if len(raw) > 4)

    n0 = len(entries0) + 1 + (1 if gps else 0)
    size0 = 2 + 12 * n0 + 4 + sum(len(r) for *_x, r in entries0 if len(r) > 4)
    exif_off = 8 + size0
    gps_off = exif_off + ifd_size(entries_exif)
    entries0.append((0x8769, 4, 1, struct.pack("<I", exif_off)))
    if gps:
        entries0.append((0x8825, 4, 1, struct.pack("<I", gps_off)))

    def pack_ifd(entries, start):
        entries = sorted(entries, key=lambda e: e[0])
        data_at = start + 2 + 12 * len(entries) + 4
        head, tail = [struct.pack("<H", len(entries))], []
        for tag, typ, count, raw in entries:
            if len(raw) <= 4:
                head.append(struct.pack("<HHI", tag, typ, count) + raw.ljust(4, b"\x00"))
            else:
                head.append(struct.pack("<HHII", tag, typ, count, data_at))
                tail.append(raw)
                data_at += len(raw)
        return b"".join(head) + b"\x00\x00\x00\x00" + b"".join(tail)

    tiff = b"II*\x00" + struct.pack("<I", 8) + pack_ifd(entries0, 8) + pack_ifd(entries_exif, exif_off)
    if gps:
        tiff += pack_ifd(entries_gps, gps_off)
    body = b"Exif\x00\x00" + tiff
    return b"\xff\xe1" + struct.pack(">H", len(body) + 2) + body


def photo(base, **exif):
    return base[:2] + exif_block(**exif) + base[2:]


# ---------------------------------------------------------------- documents

def pdf_bytes():
    """A two revision PDF: written on 2 October, then updated on the morning of the incident."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Title (Tender 2026 Final Pricing) /Author (Fahad) /Creator (Qassas Lab Writer) "
        b"/Producer (Qassas Lab PDF 1.0) /CreationDate (D:20261002101500+03'00') "
        b"/ModDate (D:20261002101500+03'00') >>",
    ]
    text = (b"BT /F1 18 Tf 72 760 Td (Dar Al Sanbouk Trading - Tender 2026) Tj ET\n"
            b"BT /F1 12 Tf 72 730 Td (Synthetic training document. Not real.) Tj ET\n"
            b"BT /F1 12 Tf 72 712 Td (Bid total: KWD 1,284,500.000) Tj ET\n")
    objs[3] = b"<< /Length %d >>\nstream\n" % len(text) + text + b"endstream"
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    # Incremental update: the Info object is rewritten with a new ModDate.
    upd = len(out)
    out += (b"6 0 obj\n<< /Title (Tender 2026 Final Pricing) /Author (Fahad) /Creator (Qassas Lab Writer) "
            b"/Producer (Qassas Lab PDF 1.0) /CreationDate (D:20261002101500+03'00') "
            b"/ModDate (D:20261004085900+03'00') >>\nendobj\n")
    xref2 = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n6 1\n%010d 00000 n \n" % upd
    out += b"trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (xref, xref2)
    return bytes(out)


def png_bytes():
    w, h = 32, 16
    rows = b"".join(b"\x00" + bytes((233, 220, 196)) * w for _ in range(h))

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
            chunk(b"tEXt", b"Comment\x00Screenshot of the bid summary") +
            chunk(b"tEXt", b"Software\x00Qassas Lab Capture") +
            chunk(b"tIME", struct.pack(">HBBBBB", 2026, 10, 4, 5, 51, 30)) +
            chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def zip_bytes(pdf):
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in (("Tender_2026_Final.pdf", pdf),
                           ("notes.txt", "المناقصة النهائية مع الأسعار\nلا ترسلها خارج الشركة\n".encode("utf-8"))):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 4, 8, 58, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


# ---------------------------------------------------------------- disk image

def laptop_image(rng, pdf, zipped):
    size = 2 * 1024 * 1024
    img = bytearray(rng.randbytes(size))
    # Zero the first sectors like a wiped boot area, and some free regions.
    img[0:65536] = bytes(65536)
    for start in (300000, 900000, 1500000):
        img[start:start + 40000] = bytes(40000)
    taken = "2026:10:03 19:12:40"
    jpg1 = photo(lab_assets.WHITEBOARD, make="QassasLab", model="QL-1 Phone", taken=taken, gps=SALMIYA)
    jpg2 = photo(lab_assets.DUNE, make="QassasLab", model="QL-1 Phone", taken="2026:09:28 17:40:05")
    chat = ("أرسل لي ملف المناقصة قبل الساعة 9 وامسح الرسالة بعدها").encode("utf-16-le")
    search = "مناقصة دار السنبوك 2026".encode("utf-8")
    ascii_bits = (b"From: it-support@" + PHISH_DOMAIN.encode() + b"\r\nTo: fahad@" + ORG_DOMAIN.encode() +
                  b"\r\nSubject: Urgent tender portal password reset\r\n\r\nReset here: https://" +
                  PHISH_DOMAIN.encode() + b"/sso/reset\r\nCall +965 5000 0000 if the link fails.\r\n"
                  b"Transfer deposit to KW00QSAS0000000000000000000000\r\n")
    placements = [
        (131072, jpg1), (262144 + 12345, ascii_bits), (300512, chat), (420000, zipped),
        (700001, jpg2), (905000, search), (1048576 + 777, pdf), (1600000, png_bytes()),
    ]
    for off, blob in placements:
        img[off:off + len(blob)] = blob
    return bytes(img), {"jpg_offsets": [131072, 700001]}


# ---------------------------------------------------------------- browser

def history_db(path):
    import sqlite3
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript("""
        PRAGMA journal_mode=DELETE;
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0, last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
            from_visit INTEGER, transition INTEGER DEFAULT 0, segment_id INTEGER, visit_duration INTEGER DEFAULT 0);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR,
            start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER,
            interrupt_reason INTEGER, end_time INTEGER, opened INTEGER, referrer VARCHAR, tab_url VARCHAR,
            mime_type VARCHAR);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term LONGVARCHAR, normalized_term LONGVARCHAR);
    """)
    visits = [
        (kwt(4, 7, 55, 12), "https://portal.%s/" % ORG_DOMAIN, "Dar Al Sanbouk Portal", 1),
        (kwt(4, 8, 2, 40), "https://www.google.example/search?q=%D9%85%D9%86%D8%A7%D9%82%D8%B5%D8%A9", "مناقصة", 1),
        (kwt(4, 8, 42, 9), "https://%s/sso/reset" % PHISH_DOMAIN, "Sanbouk Single Sign On", 0),
        (kwt(4, 8, 43, 30), "https://%s/sso/done" % PHISH_DOMAIN, "Password updated", 7),
        (kwt(4, 8, 44, 2), "https://%s/Tender_Update.zip" % FILES_DOMAIN, "", 0),
        (kwt(4, 9, 5, 55), "https://portal.%s/tenders/2026" % ORG_DOMAIN, "Tenders 2026", 1),
    ]
    for n, (t, url, title, transition) in enumerate(visits, 1):
        con.execute("INSERT INTO urls VALUES (?,?,?,?,?,?,0)", (n, url, title, 1, 1 if transition == 1 else 0, to_webkit(t)))
        con.execute("INSERT INTO visits VALUES (?,?,?,0,?,0,0)", (n, n, to_webkit(t), transition | 0x30000000))
    con.execute("INSERT INTO keyword_search_terms VALUES (2, 2, ?, ?)", ("مناقصة", "مناقصة"))
    start = kwt(4, 8, 44, 3)
    con.execute("INSERT INTO downloads VALUES (1, 'b1d3c0de-0000-4000-8000-000000000001', ?, ?, ?, 48213, 48213, 1, 0, 0, ?, 1, ?, ?, 'application/zip')",
                (r"C:\Users\fahad\Downloads\Tender_Update.zip", r"C:\Users\fahad\Downloads\Tender_Update.zip",
                 to_webkit(start), to_webkit(start + timedelta(seconds=4)),
                 "https://%s/sso/done" % PHISH_DOMAIN, "https://%s/Tender_Update.zip" % FILES_DOMAIN))
    con.commit()
    con.execute("VACUUM")
    con.close()


# ---------------------------------------------------------------- logs

def auth_log(rng):
    lines = []

    def add(t, prog, msg):
        local = t.astimezone(KUWAIT)
        lines.append("%s %2d %s srv-files %s: %s" % (local.strftime("%b"), local.day, local.strftime("%H:%M:%S"), prog, msg))

    add(kwt(4, 7, 58, 21), "sshd[1204]", "Accepted publickey for fahad from %s port 50211 ssh2" % LAPTOP_IP)
    add(kwt(4, 7, 58, 21), "sshd[1204]", "pam_unix(sshd:session): session opened for user fahad(uid=1001) by (uid=0)")
    add(kwt(4, 8, 15, 2), "sshd[1290]", "Accepted publickey for itadmin from 10.10.20.30 port 50944 ssh2")
    add(kwt(4, 8, 15, 40), "sudo", "itadmin : TTY=pts/0 ; PWD=/home/itadmin ; USER=root ; COMMAND=/usr/bin/systemctl restart smbd")
    t = kwt(4, 9, 20, 11)
    users = ["admin", "admin", "root", "admin", "administrator", "root", "backup", "admin", "fahad", "fahad", "root", "admin"]
    for k, user in enumerate(users):
        port = 51122 + k * 3
        if user in ("administrator", "backup"):
            add(t, "sshd[%d]" % (2211 + k), "Invalid user %s from %s port %d" % (user, ATTACKER_IP, port))
            add(t + timedelta(seconds=1), "sshd[%d]" % (2211 + k), "Failed password for invalid user %s from %s port %d ssh2" % (user, ATTACKER_IP, port))
        else:
            add(t, "sshd[%d]" % (2211 + k), "Failed password for %s from %s port %d ssh2" % (user, ATTACKER_IP, port))
        t += timedelta(seconds=17 + rng.randint(0, 9))
    add(kwt(4, 9, 27, 3), "sshd[2251]", "Accepted password for fahad from %s port 51190 ssh2" % ATTACKER_IP)
    add(kwt(4, 9, 27, 3), "sshd[2251]", "pam_unix(sshd:session): session opened for user fahad(uid=1001) by (uid=0)")
    add(kwt(4, 9, 29, 47), "sshd[2251]", "Received disconnect from %s port 51190:11: disconnected by user" % ATTACKER_IP)
    return "\n".join(lines) + "\n"


def windows_security():
    rows = [
        {"TimeCreated": iso(kwt(4, 7, 41, 3)), "Id": 4624, "Computer": "LAPTOP-FHD01", "TargetUserName": "fahad", "LogonType": 2, "IpAddress": "-"},
        {"TimeCreated": iso(kwt(4, 8, 46, 10)), "Id": 4688, "Computer": "LAPTOP-FHD01", "TargetUserName": "fahad",
         "NewProcessName": LNK_TARGET},
        {"TimeCreated": iso(kwt(4, 8, 46, 31)), "Id": 4688, "Computer": "LAPTOP-FHD01", "TargetUserName": "fahad",
         "NewProcessName": r"C:\Windows\System32\sc.exe"},
        {"TimeCreated": iso(kwt(4, 8, 46, 32)), "Id": 7045, "Computer": "LAPTOP-FHD01", "ServiceName": SERVICE,
         "ImagePath": r"C:\ProgramData\Sanbouk\svc.exe"},
        {"TimeCreated": iso(kwt(4, 9, 3, 15)), "Id": 4625, "Computer": "LAPTOP-FHD01", "TargetUserName": "Administrator", "LogonType": 3, "IpAddress": C2_IP},
        {"TimeCreated": iso(kwt(4, 9, 41, 2)), "Id": 1102, "Computer": "LAPTOP-FHD01", "TargetUserName": "fahad"},
    ]
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


# ---------------------------------------------------------------- network

def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ipv4(src, dst, proto, payload, ident):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0, s, d)
    head = head[:10] + struct.pack("!H", _csum(head)) + head[12:]
    return head, s, d


def frame(src, dst, proto, sport, dport, payload=b"", flags=0x18, seq=1, ack=0, ident=1):
    if proto == 17:
        seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        seg = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 64240, 0, 0) + payload
    head, s, d = _ipv4(src, dst, proto, seg, ident)
    pseudo = s + d + struct.pack("!BBH", 0, proto, len(seg))
    c = _csum(pseudo + seg)
    seg = seg[:6] + struct.pack("!H", c) + seg[8:] if proto == 17 else seg[:16] + struct.pack("!H", c) + seg[18:]
    eth = bytes.fromhex("00163e0a0b01") + bytes.fromhex("00163e5a1f15") + b"\x08\x00"
    return eth + head + seg


def dns_query(name, ident, response_ip=None):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack("!HH", 1, 1)
    if response_ip is None:
        return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(int(x) for x in response_ip.split("."))
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + q + ans


def client_hello(name, rng):
    sni = name.encode()
    ext = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    body = b"\x03\x03" + rng.randbytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def capture(rng, pdf):
    pk = []
    ident = [1]

    def add(t, *args, **kw):
        ident[0] += 1
        kw.setdefault("ident", ident[0])
        pk.append((t.timestamp(), frame(*args, **kw)))

    def https(t, server, name, sport):
        add(t, LAPTOP_IP, server, 6, sport, 443, flags=0x02, seq=1000)
        add(t + timedelta(milliseconds=38), server, LAPTOP_IP, 6, 443, sport, flags=0x12, seq=5000, ack=1001)
        add(t + timedelta(milliseconds=39), LAPTOP_IP, server, 6, sport, 443, flags=0x10, seq=1001, ack=5001)
        add(t + timedelta(milliseconds=40), LAPTOP_IP, server, 6, sport, 443, client_hello(name, rng), seq=1001, ack=5001)
        add(t + timedelta(milliseconds=95), server, LAPTOP_IP, 6, 443, sport, rng.randbytes(180), seq=5001, ack=1300)
        add(t + timedelta(milliseconds=160), LAPTOP_IP, server, 6, sport, 443, flags=0x11, seq=1300, ack=5181)

    def lookup(t, name, answer, qid):
        add(t, LAPTOP_IP, DNS_IP, 17, 53000 + qid % 1000, 53, dns_query(name, qid))
        add(t + timedelta(milliseconds=12), DNS_IP, LAPTOP_IP, 17, 53, 53000 + qid % 1000, dns_query(name, qid, answer))

    qid = 4000
    # Ordinary traffic: the company portal and mail at irregular times.
    for t in (kwt(4, 7, 55, 10), kwt(4, 8, 9, 31), kwt(4, 8, 31, 2), kwt(4, 9, 5, 53), kwt(4, 9, 22, 18)):
        qid += 1
        lookup(t, "portal." + ORG_DOMAIN, PORTAL_IP, qid)
        https(t + timedelta(milliseconds=30), PORTAL_IP, "portal." + ORG_DOMAIN, 49000 + qid % 1000)
    qid += 1
    lookup(kwt(4, 8, 42, 8), PHISH_DOMAIN, PHISH_IP, qid)
    https(kwt(4, 8, 42, 8) + timedelta(milliseconds=30), PHISH_IP, PHISH_DOMAIN, 49500)
    qid += 1
    lookup(kwt(4, 8, 44, 1), FILES_DOMAIN, PHISH_IP, qid)
    https(kwt(4, 8, 44, 1) + timedelta(milliseconds=30), PHISH_IP, FILES_DOMAIN, 49510)
    # Beaconing: a lookup and a TLS check in every 60 seconds, with small jitter.
    t = kwt(4, 8, 47, 5)
    end = kwt(4, 9, 30, 0)
    n = 0
    while t < end:
        qid += 1
        n += 1
        lookup(t, C2_DOMAIN, C2_IP, qid)
        https(t + timedelta(milliseconds=25), C2_IP, C2_DOMAIN, 50000 + n)
        t += timedelta(seconds=60 + rng.uniform(-0.6, 0.6))
    # Exfiltration: the tender PDF posted in clear HTTP.
    tx = kwt(4, 9, 15, 10)
    req = (b"POST /upload?id=FHD01 HTTP/1.1\r\nHost: " + C2_DOMAIN.encode() + b"\r\nUser-Agent: " +
           SERVICE.encode() + b"/1.0\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
           str(len(pdf)).encode() + b"\r\n\r\n" + pdf)
    add(tx, LAPTOP_IP, C2_IP, 6, 50999, 80, flags=0x02, seq=7000)
    add(tx + timedelta(milliseconds=40), C2_IP, LAPTOP_IP, 6, 80, 50999, flags=0x12, seq=9000, ack=7001)
    add(tx + timedelta(milliseconds=41), LAPTOP_IP, C2_IP, 6, 50999, 80, flags=0x10, seq=7001, ack=9001)
    add(tx + timedelta(milliseconds=42), LAPTOP_IP, C2_IP, 6, 50999, 80, req, seq=7001, ack=9001)
    add(tx + timedelta(milliseconds=150), C2_IP, LAPTOP_IP, 6, 80, 50999,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", seq=9001, ack=7001 + len(req))
    pk.sort(key=lambda p: p[0])
    return pcap.write_pcap(pk), n


# ---------------------------------------------------------------- custody

def custody_entries(image_sha):
    entries = []
    steps = [
        (kwt(4, 10, 5), "seized", "ITEM-01 laptop LAPTOP-FHD01", "Noura, incident responder", None, "Office 3, Sharq",
         "Powered on and locked. Photographed in place. Network cable removed.", None),
        (kwt(4, 10, 12), "sealed", "ITEM-01 laptop LAPTOP-FHD01", "Noura, incident responder", None, "Office 3, Sharq",
         "Bag QS-B-0041, seal QS-S-0912.", None),
        (kwt(4, 11, 40), "transferred", "ITEM-01 laptop LAPTOP-FHD01", "Noura, incident responder", "Yousef, forensic examiner",
         "Qassas lab, evidence room", "Seal intact on handover.", None),
        (kwt(4, 11, 41), "received", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None,
         "Qassas lab, evidence room", "Seal QS-S-0912 intact.", None),
        (kwt(4, 13, 0), "opened", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None, "Qassas lab, bench 2",
         "Seal QS-S-0912 cut. Drive removed and connected through a hardware write blocker.", None),
        (kwt(4, 14, 25), "imaged", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None, "Qassas lab, bench 2",
         "Raw image laptop.img written to evidence store.", image_sha),
        (kwt(4, 14, 31), "verified", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None, "Qassas lab, bench 2",
         "Source and image SHA-256 match.", image_sha),
        (kwt(4, 14, 50), "resealed", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None, "Qassas lab, bench 2",
         "Bag QS-B-0042, seal QS-S-0913.", None),
        (kwt(4, 15, 5), "stored", "ITEM-01 laptop LAPTOP-FHD01", "Yousef, forensic examiner", None, "Qassas lab, evidence room",
         "Shelf C, box 7.", None),
    ]
    for t, action, item, by, to, loc, note, digest in steps:
        entries.append(custody.make_entry(entries, action, item, by, to=to, location=loc, note=note,
                                          item_sha256=digest, time_utc=iso(t)))
    return entries


# ---------------------------------------------------------------- answers

def normalise(text):
    text = unicodedata.normalize("NFKC", str(text)).strip().lower()
    text = "".join(ch for ch in text if not ("\u064b" <= ch <= "\u0652"))
    for a, b in (("أ", "ا"), ("إ", "ا"), ("آ", "ا"), ("ة", "ه"), ("\\", "/"), ("\"", ""), ("'", "")):
        text = text.replace(a, b)
    return " ".join(text.split()).rstrip(".")


def answer_hash(qid, text):
    return hashlib.sha256(("qassas:%s:%s:%s" % (CASE_ID, qid, normalise(text))).encode("utf-8")).hexdigest()


def answers(image_sha, beacons):
    return {
        "q01": [image_sha],
        "q02": ["invoice_0921.jpg", "Documents/invoice_0921.jpg"],
        "q03": ["Salmiya", "Salmiyah", "Al Salmiya", "Salmiya, Kuwait", "السالمية", "سالمية"],
        "q04": [PHISH_DOMAIN],
        "q05": ["09:27", "9:27", "09:27:03", "9:27:03"],
        "q06": ["60", "60s", "60 seconds", "1 minute"],
        "q07": ["5", "05", "seq 5", "entry 5"],
        "q08": ["2", "two"],
        "q09": [LNK_TARGET, LNK_TARGET.replace("\\", "/")],
        "q10": ["2", "two"],
        "q11": [SERVICE],
        "q12": [str(beacons)],
    }


# ---------------------------------------------------------------- writer

def write_case(out_dir):
    """Write the full case folder and return a summary dictionary."""
    rng = random.Random(SEED)
    ev = os.path.join(out_dir, "evidence")
    for sub in ("Documents", "Pictures", "Recent", "Browser", "Logs", "Network"):
        os.makedirs(os.path.join(ev, sub), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "custody"), exist_ok=True)

    def put(rel, data):
        path = os.path.join(out_dir, rel)
        with open(path, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    pdf = pdf_bytes()
    zipped = zip_bytes(pdf)
    image, _layout = laptop_image(rng, pdf, zipped)
    image_sha = hashlib.sha256(image).hexdigest()
    put("evidence/laptop.img", image)
    put("evidence/Documents/Tender_2026_Final.pdf", pdf)
    put("evidence/Documents/invoice_0921.jpg", zipped)
    put("evidence/Pictures/IMG_2038.jpg", photo(lab_assets.DUNE, make="QassasLab", model="QL-1 Phone",
                                                  taken="2026:09:28 17:40:05"))
    put("evidence/Recent/Tender_Update.lnk", lnk.build(LNK_TARGET, kwt(4, 8, 44, 7), kwt(4, 8, 46, 9), kwt(4, 8, 44, 7),
                                                     48213 * 3, volume_label="OS", working_dir=r"C:\Users\fahad\Downloads\Tender_Update"))
    history_db(os.path.join(ev, "Browser", "History"))
    put("evidence/Logs/srv-files_auth.log", auth_log(rng))
    put("evidence/Logs/LAPTOP-FHD01_security.jsonl", windows_security())
    cap, beacons = capture(rng, pdf)
    put("evidence/Network/capture.pcap", cap)

    entries = custody_entries(image_sha)
    put("custody/custody.jsonl", "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries))
    tampered = [dict(e) for e in entries]
    tampered[4]["time_utc"] = iso(kwt(4, 12, 10))  # someone moved the opening time and did not recompute the hash
    put("custody/custody_archive_copy.jsonl", "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in tampered))

    manifest = hashing.make_manifest(ev, case=CASE_REF, examiner="Yousef, forensic examiner")
    manifest["created_utc"] = iso(kwt(4, 14, 40))
    for f in manifest["files"]:
        if f["path"] == "Browser/History":
            f["note"] = "SQLite layout can differ by SQLite version if you regenerate the case"
    hashing.write_manifest(manifest, os.path.join(out_dir, "manifest.json"))

    qa = answers(image_sha, beacons)
    with open(os.path.join(os.path.dirname(__file__), "data", "case-01.json"), encoding="utf-8") as fh:
        questions = json.load(fh)
    for q in questions["questions"]:
        q["answer_sha256"] = sorted({answer_hash(q["id"], a) for a in qa[q["id"]]})
    with open(os.path.join(out_dir, "questions.json"), "w", encoding="utf-8") as fh:
        json.dump(questions, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return {"case": CASE_REF, "dir": out_dir, "image_sha256": image_sha, "beacons": beacons,
            "files": len(manifest["files"])}


def check(questions_path, answers_given):
    """Grade a dictionary of answers {qid: text} against the hashed key."""
    with open(questions_path, encoding="utf-8") as fh:
        qs = json.load(fh)
    results = []
    for q in qs["questions"]:
        given = answers_given.get(q["id"])
        ok = given is not None and answer_hash(q["id"], given) in q["answer_sha256"]
        results.append({"id": q["id"], "answered": given is not None, "correct": ok})
    return results
