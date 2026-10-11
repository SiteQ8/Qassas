"""Pull readable text out of binary data, including Arabic.

Classic strings tools only see ASCII, so Arabic chat messages, names and
search terms inside memory dumps or unallocated space go unnoticed. This
module also reads UTF-8 and UTF-16 little endian Arabic, the two encodings
Windows, Android and iOS use most.

It also tags indicators an examiner in Kuwait looks for: URLs, domains, email
addresses, IPv4 addresses, Kuwaiti mobile numbers and Kuwaiti IBANs.
"""

import re

ASCII_RUN = rb"[\x20-\x7e\t]{%d,}"
UTF16_RUN = rb"(?:[\x20-\x7e\t]\x00|[\x00-\xff][\x06\x07\xfb\xfe]){%d,}"
UTF8_RUN = rb"(?:[\x20-\x7e\t]|[\xd8-\xdb][\x80-\xbf]){%d,}"
ARABIC = re.compile("[؀-ۿ]")

INDICATORS = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>()]{3,}", re.I),
    "email": re.compile(r"\b[\w.+-]+@(?:[\w-]+\.)+[a-z]{2,}\b", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "kw_mobile": re.compile(r"(?:\+965|00965)[\s-]?[569]\d{3}[\s-]?\d{4}\b"),
    "kw_iban": re.compile(r"\bKW\d{2}[A-Z]{4}\d{22}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|kw|sa|ae|qa|bh|om|io|info|example|xyz|top|ru|cn)\b", re.I),
}


def _decode_utf16(raw):
    return raw.decode("utf-16-le", "ignore")


def extract(data, min_len=4, encodings=("ascii", "utf8", "utf16le")):
    """Return a list of (offset, encoding, text) in offset order, without duplicates."""
    found = {}
    if "utf16le" in encodings:
        for m in re.finditer(UTF16_RUN % min_len, data):
            text = _decode_utf16(m.group())
            if ARABIC.search(text) and not looks_arabic(text):
                continue
            if len(text.strip()) >= min_len:
                found[m.start()] = ("utf16le", text)
    if "utf8" in encodings:
        for m in re.finditer(UTF8_RUN % min_len, data):
            raw = m.group()
            if not re.search(rb"[\xd8-\xdb]", raw):
                continue  # pure ASCII runs are reported by the ASCII pass
            text = raw.decode("utf-8", "ignore")
            if not looks_arabic(text):
                continue
            if len(text.strip()) >= min_len and m.start() not in found:
                found[m.start()] = ("utf8", text)
    if "ascii" in encodings:
        covered = sorted(found)
        for m in re.finditer(ASCII_RUN % min_len, data):
            if any(start <= m.start() < start + 2 * len(found[start][1]) + 2 for start in covered):
                continue
            found[m.start()] = ("ascii", m.group().decode("ascii"))
    return [(off, enc, text) for off, (enc, text) in sorted(found.items())]


ARABIC_WORD = re.compile("[\u0621-\u064A]{3,}")


def looks_arabic(text):
    """True when the text holds a real Arabic word, not stray bytes that decode as Arabic."""
    letters = [c for c in text if c.isalpha()]
    arabic = [c for c in letters if "\u0600" <= c <= "\u06FF"]
    return bool(ARABIC_WORD.search(text)) and len(arabic) >= 0.6 * len(letters)


def indicators(text):
    out = {}
    for kind, rx in INDICATORS.items():
        hits = sorted(set(rx.findall(text)))
        if kind == "domain":
            hits = [h for h in hits if not re.match(r"^\d+(\.\d+)+$", h)]
        if hits:
            out[kind] = hits
    return out


def scan(data, min_len=4):
    """Strings plus a summary of indicators and how much Arabic text was found."""
    items = extract(data, min_len)
    joined = "\n".join(t for _, _, t in items)
    return {
        "count": len(items),
        "arabic": [{"offset": o, "encoding": e, "text": t} for o, e, t in items if looks_arabic(t)],
        "indicators": indicators(joined),
        "strings": [{"offset": o, "encoding": e, "text": t} for o, e, t in items],
    }
