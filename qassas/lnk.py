"""Parse Windows shortcut files (MS-SHLLINK).

Windows creates a shortcut in the Recent folder whenever a user opens a file.
The shortcut keeps the target's path, size and timestamps and the volume it
lived on, even after the target itself is deleted or the USB stick is gone.
That makes LNK files strong evidence that a user opened a particular file.
"""

import struct

from .timeutil import from_filetime, iso

FLAGS = ["HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir",
         "HasArguments", "HasIconLocation", "IsUnicode"]
DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}
CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _cstr(data, offset):
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("cp1252", "replace")


def _wstr(data, offset):
    end = offset
    while data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[offset:end].decode("utf-16-le", "replace")


def parse_bytes(data):
    if len(data) < 76 or struct.unpack("<I", data[:4])[0] != 0x4C or data[4:20] != CLSID:
        raise ValueError("not a Windows shortcut")
    flags_value, attrs = struct.unpack("<II", data[20:28])
    created, accessed, written = struct.unpack("<QQQ", data[28:52])
    size = struct.unpack("<I", data[52:56])[0]
    flags = {name for bit, name in enumerate(FLAGS) if flags_value & (1 << bit)}
    out = {
        "flags": sorted(flags),
        "target_created_utc": iso(from_filetime(created)),
        "target_accessed_utc": iso(from_filetime(accessed)),
        "target_modified_utc": iso(from_filetime(written)),
        "target_size": size,
        "target_attributes": attrs,
    }
    pos = 76
    if "HasLinkTargetIDList" in flags:
        pos += 2 + struct.unpack("<H", data[pos:pos + 2])[0]
    if "HasLinkInfo" in flags:
        info = pos
        info_size, header_size, info_flags, vol_off, base_off, _net_off, _suffix_off = \
            struct.unpack("<IIIIIII", data[info:info + 28])
        if info_flags & 1:
            v = info + vol_off
            _vsize, dtype, serial, label_off = struct.unpack("<IIII", data[v:v + 16])
            out["drive_type"] = DRIVE_TYPES.get(dtype, str(dtype))
            out["volume_serial"] = "%04X-%04X" % (serial >> 16, serial & 0xFFFF)
            out["volume_label"] = _cstr(data, v + label_off)
            out["local_base_path"] = _cstr(data, info + base_off)
            if header_size >= 0x24:
                base_u = struct.unpack("<I", data[info + 28:info + 32])[0]
                if base_u:
                    out["local_base_path"] = _wstr(data, info + base_u)
        pos += info_size
    unicode = "IsUnicode" in flags
    for flag, key in (("HasName", "name"), ("HasRelativePath", "relative_path"),
                      ("HasWorkingDir", "working_dir"), ("HasArguments", "arguments"),
                      ("HasIconLocation", "icon_location")):
        if flag in flags:
            count = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2
            width = 2 if unicode else 1
            raw = data[pos:pos + count * width]
            out[key] = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
            pos += count * width
    return out


def parse(path):
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())


def build(target_path, created, accessed, written, size, volume_label="OS", serial=0x1A2B3C4D,
          drive_type=3, working_dir=None, arguments=None):
    """Write a minimal but valid shortcut. Used to make the synthetic lab evidence."""
    from .timeutil import to_filetime
    flags = (1 << 1) | (1 << 7)  # HasLinkInfo, IsUnicode
    if working_dir:
        flags |= 1 << 4
    if arguments:
        flags |= 1 << 5
    header = struct.pack("<I16sIIQQQIIIH", 0x4C, CLSID, flags, 0x20, to_filetime(created),
                         to_filetime(accessed), to_filetime(written), size, 0, 1, 0) + b"\x00" * 10
    label = volume_label.encode("cp1252") + b"\x00"
    volume = struct.pack("<IIII", 16 + len(label), drive_type, serial, 16) + label
    base = target_path.encode("cp1252", "replace") + b"\x00"
    base_u = target_path.encode("utf-16-le") + b"\x00\x00"
    header_size = 0x24
    vol_off = header_size
    base_off = vol_off + len(volume)
    suffix_off = base_off + len(base)
    base_u_off = suffix_off + 1
    body = volume + base + b"\x00" + base_u
    info = struct.pack("<IIIIIIIII", header_size + len(body), header_size, 1, vol_off, base_off, 0,
                       suffix_off, base_u_off, 0) + body
    strings = b""
    for value in (working_dir, arguments):
        if value:
            strings += struct.pack("<H", len(value)) + value.encode("utf-16-le")
    return header + info + strings + b"\x00\x00\x00\x00"
