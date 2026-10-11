"""Read packet captures and summarise what the network saw.

The classic pcap format is a 24 byte file header followed by records, each
with a timestamp and the captured bytes. This reader handles Ethernet, Linux
cooked and raw IP captures, decodes IPv4, TCP and UDP, and extracts the
details an examiner reads first: DNS lookups, TLS server names, HTTP requests
and conversations. It also looks for beaconing, the regular check ins malware
makes to its command server.
"""

import statistics
import struct
from collections import defaultdict

from .timeutil import from_unix, iso

LINK_ETHERNET, LINK_RAW, LINK_SLL = 1, 101, 113


def read_packets(data):
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        e, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        e, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        e, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        e, nano = ">", True
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise ValueError("pcapng is not supported, convert it with: editcap -F pcap in.pcapng out.pcap")
    else:
        raise ValueError("not a pcap file")
    linktype = struct.unpack(e + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[pos:pos + 16])
        pos += 16
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[pos:pos + incl]
        pos += incl


def _ip_payload(linktype, frame):
    if linktype == LINK_ETHERNET:
        etype = struct.unpack(">H", frame[12:14])[0]
        off = 14
        if etype == 0x8100:
            etype = struct.unpack(">H", frame[16:18])[0]
            off = 18
        return frame[off:] if etype == 0x0800 else None
    if linktype == LINK_SLL:
        return frame[16:] if struct.unpack(">H", frame[14:16])[0] == 0x0800 else None
    if linktype == LINK_RAW:
        return frame if frame[:1] and frame[0] >> 4 == 4 else None
    return None


def _ip(b):
    return ".".join(str(x) for x in b)


def decode(ts, linktype, frame):
    ip = _ip_payload(linktype, frame)
    if not ip or len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    pkt = {"ts": ts, "src": _ip(ip[12:16]), "dst": _ip(ip[16:20]), "proto": proto, "len": len(frame)}
    seg = ip[ihl:]
    if proto == 6 and len(seg) >= 20:
        sport, dport, _seq, _ack, off_flags = struct.unpack(">HHIIH", seg[:14])
        data_off = (off_flags >> 12) * 4
        pkt.update(sport=sport, dport=dport, flags=off_flags & 0x3F, payload=seg[data_off:])
    elif proto == 17 and len(seg) >= 8:
        sport, dport = struct.unpack(">HH", seg[:4])
        pkt.update(sport=sport, dport=dport, payload=seg[8:])
    else:
        pkt["payload"] = b""
    return pkt


def _dns_name(msg, off, depth=0):
    labels = []
    while off < len(msg) and depth < 20:
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            name, _ = _dns_name(msg, ptr, depth + 1)
            labels.append(name)
            return ".".join(labels), off + 2
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), off


def dns(payload):
    if len(payload) < 12:
        return None
    _id, flags, qd, an = struct.unpack(">HHHH", payload[:8])
    if qd == 0:
        return None
    name, off = _dns_name(payload, 12)
    qtype = struct.unpack(">H", payload[off:off + 2])[0] if off + 2 <= len(payload) else 0
    out = {"query": name.lower(), "qtype": {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 15: "MX"}.get(qtype, str(qtype)),
           "response": bool(flags & 0x8000), "answers": []}
    if out["response"]:
        off += 4
        for _ in range(an):
            if off + 12 > len(payload):
                break
            _n, off = _dns_name(payload, off)
            atype, _cls, _ttl, rdlen = struct.unpack(">HHIH", payload[off:off + 10])
            off += 10
            if atype == 1 and rdlen == 4:
                out["answers"].append(_ip(payload[off:off + 4]))
            off += rdlen
    return out


def tls_sni(payload):
    """Server name from a TLS ClientHello, sent in clear text before encryption starts."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    p = 43
    p += 1 + payload[p]  # session id
    if p + 2 > len(payload):
        return None
    p += 2 + struct.unpack(">H", payload[p:p + 2])[0]  # cipher suites
    p += 1 + payload[p]  # compression methods
    end = p + 2 + struct.unpack(">H", payload[p:p + 2])[0]
    p += 2
    while p + 4 <= min(end, len(payload)):
        etype, elen = struct.unpack(">HH", payload[p:p + 4])
        if etype == 0:
            name_len = struct.unpack(">H", payload[p + 7:p + 9])[0]
            return payload[p + 9:p + 9 + name_len].decode("ascii", "replace").lower()
        p += 4 + elen
    return None


def http_request(payload):
    head = payload[:2048]
    for verb in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS "):
        if head.startswith(verb):
            lines = head.split(b"\r\n")
            method, path = lines[0].split(b" ")[:2]
            host = ua = None
            for line in lines[1:]:
                low = line.lower()
                if low.startswith(b"host:"):
                    host = line[5:].strip().decode("ascii", "replace")
                elif low.startswith(b"user-agent:"):
                    ua = line[11:].strip().decode("ascii", "replace")
            return {"method": method.decode(), "path": path.decode("ascii", "replace"), "host": host, "user_agent": ua}
    return None


def analyse(data, beacon_min=6, beacon_cv=0.15):
    packets = []
    for ts, lt, frame in read_packets(data):
        p = decode(ts, lt, frame)
        if p:
            packets.append(p)
    convs = {}
    dns_q, sni, http = [], [], []
    starts = defaultdict(list)
    for p in packets:
        key = (p["src"], p["dst"], p["proto"], p.get("dport"))
        c = convs.setdefault(key, {"src": p["src"], "dst": p["dst"], "proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(p["proto"], str(p["proto"])),
                                   "dport": p.get("dport"), "packets": 0, "bytes": 0, "first": p["ts"], "last": p["ts"]})
        c["packets"] += 1
        c["bytes"] += p["len"]
        c["last"] = p["ts"]
        pay = p.get("payload") or b""
        if p["proto"] == 17 and 53 in (p.get("sport"), p.get("dport")):
            d = dns(pay)
            if d and not d["response"]:
                dns_q.append({"time_utc": iso(from_unix(p["ts"])), "client": p["src"], "server": p["dst"], **d})
                starts[("dns", p["src"], d["query"])].append(p["ts"])
        if p["proto"] == 6:
            if p.get("flags") == 0x02:
                starts[("tcp", p["src"], "%s:%s" % (p["dst"], p["dport"]))].append(p["ts"])
            name = tls_sni(pay)
            if name:
                sni.append({"time_utc": iso(from_unix(p["ts"])), "client": p["src"], "server": p["dst"], "sni": name})
            req = http_request(pay)
            if req:
                http.append({"time_utc": iso(from_unix(p["ts"])), "client": p["src"], "server": p["dst"],
                             "bytes": len(pay), **req})
    beacons = []
    for (kind, src, target), times in starts.items():
        if len(times) < beacon_min:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0.5]
        if len(gaps) < beacon_min - 1:
            continue
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv <= beacon_cv:
            beacons.append({"kind": kind, "client": src, "target": target, "count": len(times),
                            "interval_s": round(mean, 1), "jitter_cv": round(cv, 3),
                            "first_utc": iso(from_unix(times[0])), "last_utc": iso(from_unix(times[-1]))})
    conv_list = sorted(convs.values(), key=lambda c: -c["bytes"])
    for c in conv_list:
        c["first"] = iso(from_unix(c["first"]))
        c["last"] = iso(from_unix(c["last"]))
    return {"packets": len(packets), "conversations": conv_list, "dns": dns_q, "tls_sni": sni,
            "http": http, "beacons": sorted(beacons, key=lambda b: b["first_utc"])}


def write_pcap(packets, linktype=LINK_ETHERNET):
    """Write a classic little endian pcap from (timestamp, frame bytes) pairs. Used by the lab."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for ts, frame in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
    return b"".join(out)
