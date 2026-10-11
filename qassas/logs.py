"""Analyse authentication logs: Linux auth.log and exported Windows events.

Login records answer the first questions of most investigations: who got in,
from where, when, and after how many failed tries. This module parses both
sources into one event list and flags the patterns an examiner checks first:
password guessing followed by a success, logins from new addresses, privilege
use and cleared logs.
"""

import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

from .timeutil import KUWAIT, UTC, iso, parse_iso

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
SYSLOG = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) ([\w./-]+)(?:\[\d+\])?: (.*)$")
ISO_SYSLOG = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:\d\d)) (\S+) ([\w./-]+)(?:\[\d+\])?: (.*)$")
PATTERNS = [
    ("ssh_failed", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")),
    ("ssh_accepted", re.compile(r"Accepted (password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")),
    ("ssh_invalid_user", re.compile(r"Invalid user (\S*) from (\S+)")),
    ("sudo", re.compile(r"^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$")),
    ("session_opened", re.compile(r"session opened for user (\S+)")),
]

WINDOWS_EVENTS = {
    4624: ("logon_success", "An account logged on", "تسجيل دخول ناجح لحساب"),
    4625: ("logon_failed", "An account failed to log on", "محاولة دخول فاشلة لحساب"),
    4634: ("logoff", "An account logged off", "تسجيل خروج حساب"),
    4648: ("explicit_credentials", "A logon used explicit credentials", "دخول باستخدام بيانات اعتماد صريحة"),
    4672: ("special_privileges", "Special privileges assigned to a new logon", "منح صلاحيات خاصة لجلسة دخول جديدة"),
    4688: ("process_created", "A new process was created", "إنشاء عملية جديدة"),
    4720: ("account_created", "A user account was created", "إنشاء حساب مستخدم"),
    4732: ("added_to_group", "A member was added to a security enabled local group", "إضافة عضو إلى مجموعة أمنية محلية"),
    1102: ("log_cleared", "The audit log was cleared", "مسح سجل التدقيق"),
    7045: ("service_installed", "A service was installed in the system", "تثبيت خدمة في النظام"),
}
LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock",
               8: "network_cleartext", 9: "new_credentials", 10: "remote_interactive", 11: "cached_interactive"}


def parse_auth_log(text, year, tz=KUWAIT):
    """Parse a Linux auth.log. Syslog lines carry no year or zone, so both are given.

    The host's own time zone must be confirmed from its configuration, never
    assumed. The default here is Kuwait time because the lab servers use it.
    """
    events = []
    for line in text.splitlines():
        m = ISO_SYSLOG.match(line)
        if m:
            when, host, prog, msg = parse_iso(m.group(1)), m.group(2), m.group(3), m.group(4)
        else:
            m = SYSLOG.match(line)
            if not m:
                continue
            mon, day, hh, mm, ss, host, prog, msg = m.groups()
            when = datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
        for kind, rx in PATTERNS:
            p = rx.search(msg)
            if not p:
                continue
            ev = {"time_utc": iso(when.astimezone(UTC)), "host": host, "program": prog, "type": kind, "raw": line}
            if kind == "ssh_failed":
                ev.update(user=p.group(1), source_ip=p.group(2))
            elif kind == "ssh_accepted":
                ev.update(method=p.group(1), user=p.group(2), source_ip=p.group(3))
            elif kind == "ssh_invalid_user":
                ev.update(user=p.group(1), source_ip=p.group(2))
            elif kind == "sudo":
                ev.update(user=p.group(1), run_as=p.group(2), command=p.group(3))
            elif kind == "session_opened":
                ev.update(user=p.group(1))
            events.append(ev)
            break
    return events


def parse_windows_export(path):
    """Read Windows Security events exported as JSON Lines or CSV.

    Expected fields: TimeCreated (ISO 8601), Id or EventID, Computer, and for
    logons TargetUserName, IpAddress and LogonType. Get-WinEvent piped to
    ConvertTo-Json or Export-Csv produces this shape.
    """
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    rows = []
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(text)
            rows = data if isinstance(data, list) else [data]
        except ValueError:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        rows = list(csv.DictReader(text.splitlines()))
    events = []
    for r in rows:
        eid = int(r.get("Id") or r.get("EventID") or 0)
        if eid not in WINDOWS_EVENTS:
            continue
        kind, en, ar = WINDOWS_EVENTS[eid]
        ev = {"time_utc": iso(parse_iso(r["TimeCreated"]).astimezone(UTC)), "host": r.get("Computer"),
              "program": "Security", "type": kind, "event_id": eid, "summary": {"en": en, "ar": ar}}
        if r.get("TargetUserName"):
            ev["user"] = r["TargetUserName"]
        ip = r.get("IpAddress")
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            ev["source_ip"] = ip
        if r.get("LogonType"):
            ev["logon_type"] = LOGON_TYPES.get(int(r["LogonType"]), str(r["LogonType"]))
        if r.get("NewProcessName"):
            ev["process"] = r["NewProcessName"]
        if r.get("ServiceName"):
            ev["service"] = r["ServiceName"]
            ev["image_path"] = r.get("ImagePath")
        events.append(ev)
    events.sort(key=lambda e: e["time_utc"])
    return events


def findings(events, threshold=5, window_minutes=10):
    """Flag password guessing, guessing followed by success, privilege use and cleared logs."""
    out = []
    fails = defaultdict(list)
    for ev in events:
        t = parse_iso(ev["time_utc"])
        if ev["type"] in ("ssh_failed", "ssh_invalid_user", "logon_failed") and ev.get("source_ip"):
            fails[ev["source_ip"]].append(t)
        if ev["type"] in ("ssh_accepted", "logon_success") and ev.get("source_ip"):
            recent = [f for f in fails.get(ev["source_ip"], []) if t - timedelta(minutes=window_minutes * 6) <= f <= t]
            if len(recent) >= threshold:
                out.append({"code": "guess_then_success", "severity": "high", "time_utc": ev["time_utc"],
                            "source_ip": ev["source_ip"], "user": ev.get("user"), "failures_before": len(recent),
                            "first_failure_utc": iso(min(recent))})
        if ev["type"] == "log_cleared":
            out.append({"code": "log_cleared", "severity": "high", "time_utc": ev["time_utc"], "user": ev.get("user")})
        if ev["type"] == "sudo" and re.search(r"(useradd|passwd|visudo|curl|wget|nc |chmod \+s|crontab)", ev.get("command", "")):
            out.append({"code": "risky_sudo", "severity": "medium", "time_utc": ev["time_utc"],
                        "user": ev.get("user"), "command": ev.get("command")})
    for ip, times in fails.items():
        times.sort()
        for i in range(len(times)):
            j = i
            while j < len(times) and times[j] - times[i] <= timedelta(minutes=window_minutes):
                j += 1
            if j - i >= threshold:
                out.append({"code": "password_guessing", "severity": "medium", "source_ip": ip,
                            "time_utc": iso(times[i]), "attempts": j - i, "window_minutes": window_minutes})
                break
    out.sort(key=lambda f: f["time_utc"])
    return out


FINDING_TEXT = {
    "password_guessing": {"en": "Many failed logins from one address in a short window",
                          "ar": "محاولات دخول فاشلة كثيرة من عنوان واحد في وقت قصير"},
    "guess_then_success": {"en": "A successful login from an address that was guessing passwords",
                           "ar": "دخول ناجح من عنوان كان يخمّن كلمات المرور"},
    "log_cleared": {"en": "The security log was cleared",
                    "ar": "مُسح السجل الأمني"},
    "risky_sudo": {"en": "A privileged command that changes accounts or fetches code",
                   "ar": "أمر بصلاحيات عالية يغيّر الحسابات أو يجلب برمجيات"},
}
