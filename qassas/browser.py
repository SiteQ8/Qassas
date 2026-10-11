"""Read browser history databases (Chromium based browsers and Firefox).

Chrome, Edge, Brave and Opera keep history in an SQLite file named History.
Firefox uses places.sqlite. Both record each URL, every visit to it and its
time, and Chromium also records downloads and search terms.

The database is always copied before it is opened, because opening the
original with SQLite can write to it and change the evidence.
"""

import os
import shutil
import sqlite3
import tempfile

from .timeutil import from_prtime, from_webkit, iso

TRANSITIONS = {0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe",
               5: "generated", 6: "auto_toplevel", 7: "form_submit", 8: "reload", 9: "keyword",
               10: "keyword_generated"}


def _open_copy(path):
    tmp = tempfile.mkdtemp(prefix="qassas-")
    copy = os.path.join(tmp, "copy.sqlite")
    shutil.copyfile(path, copy)
    for suffix in ("-wal", "-journal"):
        if os.path.exists(path + suffix):
            shutil.copyfile(path + suffix, copy + suffix)
    uri = "file:%s?mode=ro" % copy
    return sqlite3.connect(uri, uri=True), tmp


def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def read_history(path):
    con, tmp = _open_copy(path)
    try:
        tables = _tables(con)
        if {"urls", "visits"} <= tables:
            return _chromium(con, tables)
        if {"moz_places", "moz_historyvisits"} <= tables:
            return _firefox(con)
        raise ValueError("not a Chromium History or Firefox places database")
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _chromium(con, tables):
    visits = []
    for url, title, vtime, transition, count in con.execute(
            "SELECT u.url, u.title, v.visit_time, v.transition, u.visit_count "
            "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time"):
        visits.append({"time_utc": iso(from_webkit(vtime)), "url": url, "title": title,
                       "transition": TRANSITIONS.get(transition & 0xFF, str(transition & 0xFF)),
                       "visit_count": count})
    downloads = []
    if "downloads" in tables:
        for target, start, end, received, total, tab_url, referrer in con.execute(
                "SELECT target_path, start_time, end_time, received_bytes, total_bytes, tab_url, referrer "
                "FROM downloads ORDER BY start_time"):
            downloads.append({"time_utc": iso(from_webkit(start)), "end_utc": iso(from_webkit(end)),
                              "target_path": target, "bytes": total or received,
                              "tab_url": tab_url, "referrer": referrer})
    searches = []
    if "keyword_search_terms" in tables:
        for term, url, vtime in con.execute(
                "SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                "JOIN urls u ON u.id = k.url_id ORDER BY u.last_visit_time"):
            searches.append({"time_utc": iso(from_webkit(vtime)), "term": term, "url": url})
    return {"browser": "chromium", "visits": visits, "downloads": downloads, "searches": searches}


def _firefox(con):
    visits = []
    for url, title, vtime, vtype in con.execute(
            "SELECT p.url, p.title, v.visit_date, v.visit_type FROM moz_historyvisits v "
            "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date"):
        visits.append({"time_utc": iso(from_prtime(vtime)), "url": url, "title": title,
                       "transition": str(vtype)})
    return {"browser": "firefox", "visits": visits, "downloads": [], "searches": []}
