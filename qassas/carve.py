"""Recover files from raw bytes by their headers and footers.

When a file is deleted, the file system usually forgets where it was but the
bytes stay on disk until something overwrites them. Carving ignores the file
system and searches the raw data for known starts and ends of files. It works
best on files stored in one contiguous run, which this module assumes.
"""

import hashlib
import os
import struct

MAX_SIZE = 20 * 1024 * 1024


def _jpeg_end(data, start):
    """Walk JPEG segments to the End Of Image marker.

    Walking the markers instead of searching for FF D9 avoids stopping early
    at an embedded thumbnail, which is a common carving error.
    """
    i = start + 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xD9:
            return i + 2
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        i += 2 + length
        if marker == 0xDA:  # start of scan: entropy coded data until a real marker
            while i + 1 < n:
                if data[i] == 0xFF and data[i + 1] not in (0x00,) and not (0xD0 <= data[i + 1] <= 0xD7):
                    break
                i += 1
        if i - start > MAX_SIZE:
            return None
    return None


def _png_end(data, start):
    i = start + 8
    while i + 12 <= len(data):
        length = struct.unpack(">I", data[i:i + 4])[0]
        kind = data[i + 4:i + 8]
        i += 12 + length
        if kind == b"IEND":
            return i
        if length > MAX_SIZE:
            return None
    return None


def _gif_end(data, start):
    end = data.find(b"\x00\x3b", start + 6, start + MAX_SIZE)
    return end + 2 if end != -1 else None


def _pdf_end(data, start):
    """The last %%EOF before the next PDF header, so updated PDFs stay whole."""
    limit = data.find(b"%PDF-", start + 5)
    if limit == -1:
        limit = min(len(data), start + MAX_SIZE)
    end = data.rfind(b"%%EOF", start, limit)
    if end == -1:
        return None
    end += 5
    while end < len(data) and data[end:end + 1] in (b"\r", b"\n"):
        end += 1
    return end


def _zip_end(data, start):
    i = data.find(b"PK\x05\x06", start, start + MAX_SIZE)
    if i == -1 or i + 22 > len(data):
        return None
    comment = struct.unpack("<H", data[i + 20:i + 22])[0]
    return i + 22 + comment


CARVERS = {
    "jpg": (b"\xff\xd8\xff", _jpeg_end),
    "png": (b"\x89PNG\r\n\x1a\n", _png_end),
    "gif": (b"GIF8", _gif_end),
    "pdf": (b"%PDF-", _pdf_end),
    "zip": (b"PK\x03\x04", _zip_end),
}


def carve_bytes(data, types=None):
    """Return a list of found files as dictionaries with offset, size, type, sha256 and bytes."""
    found = []
    claimed = []
    for kind in (types or CARVERS):
        header, finder = CARVERS[kind]
        pos = 0
        while True:
            start = data.find(header, pos)
            if start == -1:
                break
            pos = start + 1
            if any(a <= start < b for a, b in claimed):
                continue
            end = finder(data, start)
            if not end or end <= start:
                continue
            blob = data[start:end]
            found.append({"type": kind, "offset": start, "size": len(blob),
                          "sha256": hashlib.sha256(blob).hexdigest(), "data": blob})
            claimed.append((start, end))
            pos = end
    found.sort(key=lambda f: f["offset"])
    return found


def carve(path, out_dir=None, types=None):
    with open(path, "rb") as fh:
        data = fh.read()
    found = carve_bytes(data, types)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        for n, item in enumerate(found, 1):
            name = "carved_%03d_at_%d.%s" % (n, item["offset"], item["type"])
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(item["data"])
            item["file"] = name
    for item in found:
        item.pop("data", None)
    return found
