"""Read the metadata files carry about themselves.

Photos record the camera, the time and often the place. PDFs and Office
documents record their author, the software that made them and when they were
created and saved. Metadata can be forged, so treat it as a lead to confirm
with other evidence, never as proof on its own.
"""

import re
import struct
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

TIFF_TYPES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
IFD0_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software", 0x0132: "datetime",
             0x013B: "artist", 0x8298: "copyright", 0x010E: "description"}
EXIF_TAGS = {0x9003: "datetime_original", 0x9004: "datetime_digitized",
             0x9010: "offset_time", 0x9011: "offset_time_original", 0xA431: "body_serial",
             0xA434: "lens_model", 0x927C: "maker_note_present"}
GPS_TAGS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon", 5: "alt_ref", 6: "alt",
            7: "gps_time", 0x1D: "gps_date"}


class _Tiff:
    def __init__(self, data):
        self.d = data
        self.e = "<" if data[:2] == b"II" else ">"
        if data[2:4] not in (b"\x2a\x00", b"\x00\x2a"):
            raise ValueError("not a TIFF header")

    def u16(self, o):
        return struct.unpack(self.e + "H", self.d[o:o + 2])[0]

    def u32(self, o):
        return struct.unpack(self.e + "I", self.d[o:o + 4])[0]

    def ifd(self, offset):
        out = {}
        count = self.u16(offset)
        for k in range(count):
            p = offset + 2 + 12 * k
            tag, typ, n = self.u16(p), self.u16(p + 2), self.u32(p + 4)
            size = TIFF_TYPES.get(typ, 1) * n
            where = p + 8 if size <= 4 else self.u32(p + 8)
            raw = self.d[where:where + size]
            out[tag] = self.value(typ, n, raw, p + 8)
        return out

    def value(self, typ, n, raw, inline):
        if typ == 2:
            return raw.rstrip(b"\x00").decode("utf-8", "replace").strip()
        if typ == 3:
            vals = [struct.unpack(self.e + "H", raw[2 * i:2 * i + 2])[0] for i in range(n)]
        elif typ in (4, 9):
            vals = [struct.unpack(self.e + ("I" if typ == 4 else "i"), raw[4 * i:4 * i + 4])[0] for i in range(n)]
        elif typ in (5, 10):
            vals = []
            for i in range(n):
                a, b = struct.unpack(self.e + ("II" if typ == 5 else "ii"), raw[8 * i:8 * i + 8])
                vals.append(a / b if b else 0.0)
        elif typ == 1 or typ == 7:
            vals = list(raw)
        else:
            vals = [self.u32(inline)]
        return vals[0] if n == 1 else vals


def _dms(values, ref):
    if not isinstance(values, list) or len(values) != 3:
        return None
    deg = values[0] + values[1] / 60.0 + values[2] / 3600.0
    return round(-deg if ref in ("S", "W") else deg, 6)


def exif_from_tiff(tiff_bytes):
    t = _Tiff(tiff_bytes)
    ifd0 = t.ifd(t.u32(4))
    out = {name: ifd0[tag] for tag, name in IFD0_TAGS.items() if tag in ifd0}
    if 0x8769 in ifd0:
        sub = t.ifd(ifd0[0x8769])
        for tag, name in EXIF_TAGS.items():
            if tag in sub:
                out[name] = True if tag == 0x927C else sub[tag]
    if 0x8825 in ifd0:
        gps = {GPS_TAGS[k]: v for k, v in t.ifd(ifd0[0x8825]).items() if k in GPS_TAGS}
        lat = _dms(gps.get("lat"), gps.get("lat_ref"))
        lon = _dms(gps.get("lon"), gps.get("lon_ref"))
        if lat is not None and lon is not None:
            from .geo import nearest
            out["gps"] = {"lat": lat, "lon": lon}
            area = nearest(lat, lon)
            if area:
                out["gps"]["nearest_area"] = area
            if isinstance(gps.get("alt"), float):
                out["gps"]["alt_m"] = round(gps["alt"], 1)
            if gps.get("gps_date"):
                out["gps"]["date"] = gps["gps_date"]
    return out


def jpeg_exif(data):
    """Find the Exif APP1 segment of a JPEG and decode it."""
    if data[:2] != b"\xff\xd8":
        return {}
    i = 2
    while i + 4 <= len(data) and data[i] == 0xFF:
        marker = data[i + 1]
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return exif_from_tiff(data[i + 10:i + 2 + length])
        if marker == 0xDA:
            break
        i += 2 + length
    return {}


def exif_time(text, offset=None):
    """Turn '2026:10:04 14:22:10' plus an optional '+03:00' into an aware datetime."""
    try:
        dt = datetime.strptime(text, "%Y:%m:%d %H:%M:%S")
    except (TypeError, ValueError):
        return None
    if offset and re.match(r"^[+-]\d\d:\d\d$", offset):
        sign = 1 if offset[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
        return dt.replace(tzinfo=tz)
    return dt


def png_text(data):
    out = {}
    i = 8
    while i + 12 <= len(data):
        length = struct.unpack(">I", data[i:i + 4])[0]
        kind = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + length]
        if kind == b"tEXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            out[k.decode("latin-1")] = v.decode("latin-1")
        elif kind == b"zTXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            out[k.decode("latin-1")] = zlib.decompress(v[1:]).decode("latin-1")
        elif kind == b"iTXt" and b"\x00" in body:
            k, rest = body.split(b"\x00", 1)
            flag = rest[0]
            rest = rest[2:]
            _lang, rest = rest.split(b"\x00", 1)
            _tr, text = rest.split(b"\x00", 1)
            out[k.decode("latin-1")] = (zlib.decompress(text) if flag else text).decode("utf-8")
        elif kind == b"tIME" and length == 7:
            y, mo, d, h, mi, s = struct.unpack(">HBBBBB", body)
            out["tIME"] = "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, mo, d, h, mi, s)
        elif kind == b"IEND":
            break
        i += 12 + length
    return out


PDF_KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate")


def _pdf_string(raw):
    raw = raw.strip()
    if raw.startswith("<") and raw.endswith(">"):
        b = bytes.fromhex(re.sub(r"\s", "", raw[1:-1]))
        if b[:2] == b"\xfe\xff":
            return b[2:].decode("utf-16-be", "replace")
        return b.decode("latin-1")
    if raw.startswith("(") and raw.endswith(")"):
        s = raw[1:-1]
        b = s.encode("latin-1", "replace")
        if b[:2] == b"\xfe\xff":
            return b[2:].decode("utf-16-be", "replace")
        return re.sub(r"\\([()\\])", r"\1", s)
    return raw


def pdf_date(text):
    """PDF dates look like D:20261004091500+03'00'."""
    m = re.match(r"D:(\d{4})(\d\d)?(\d\d)?(\d\d)?(\d\d)?(\d\d)?([Z+-])?(\d\d)?'?(\d\d)?", text or "")
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) if x else dflt for x, dflt in zip(m.groups()[:6], (0, 1, 1, 0, 0, 0)))
    tz = None
    if m.group(7) == "Z":
        tz = timezone.utc
    elif m.group(7) and m.group(7) in "+-" and m.group(8):
        sign = 1 if m.group(7) == "+" else -1
        tz = timezone(sign * timedelta(hours=int(m.group(8)), minutes=int(m.group(9) or 0)))
    return datetime(y, mo, d, h, mi, s, tzinfo=tz)


def pdf_info(data):
    text = data.decode("latin-1")
    out = {}
    for key in PDF_KEYS:
        matches = re.findall(r"/%s\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)" % key, text)
        if matches:
            out[key.lower()] = _pdf_string(matches[-1])
    out["revisions"] = text.count("%%EOF")
    m = re.match(r"%PDF-(\d\.\d)", text)
    if m:
        out["version"] = m.group(1)
    return out


NS = {"cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
      "dc": "http://purl.org/dc/elements/1.1/",
      "dcterms": "http://purl.org/dc/terms/",
      "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}


def ooxml_core(path_or_file):
    out = {}
    with zipfile.ZipFile(path_or_file) as zf:
        names = set(zf.namelist())
        if "docProps/core.xml" in names:
            root = ElementTree.fromstring(zf.read("docProps/core.xml"))
            for tag, key in (("dc:title", "title"), ("dc:creator", "creator"),
                             ("cp:lastModifiedBy", "last_modified_by"), ("cp:revision", "revision"),
                             ("dcterms:created", "created"), ("dcterms:modified", "modified"),
                             ("cp:lastPrinted", "last_printed")):
                el = root.find(tag, NS)
                if el is not None and el.text:
                    out[key] = el.text
        if "docProps/app.xml" in names:
            root = ElementTree.fromstring(zf.read("docProps/app.xml"))
            for tag, key in (("ep:Application", "application"), ("ep:Company", "company"),
                             ("ep:TotalTime", "total_edit_minutes")):
                el = root.find(tag, NS)
                if el is not None and el.text:
                    out[key] = el.text
    return out


def extract(path):
    """Detect the type and return its metadata with a 'kind' key."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:3] == b"\xff\xd8\xff":
        return {"kind": "jpeg", **jpeg_exif(data)}
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return {"kind": "png", **png_text(data)}
    if data[:5] == b"%PDF-":
        return {"kind": "pdf", **pdf_info(data)}
    if data[:4] == b"PK\x03\x04":
        try:
            return {"kind": "ooxml", **ooxml_core(path)}
        except (zipfile.BadZipFile, KeyError, ElementTree.ParseError):
            return {"kind": "zip"}
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return {"kind": "tiff", **exif_from_tiff(data)}
    return {"kind": "unknown"}
