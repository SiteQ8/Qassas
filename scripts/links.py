#!/usr/bin/env python3
"""Check every external link in the data. A 404 or 410 fails; anything else is reported.

Government sites in the Gulf often refuse automated requests or are slow from abroad,
so a refusal or timeout is listed for a human to check rather than failing the build.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from qassas.data_files import load  # noqa: E402


def urls():
    out = {}
    for r in load("legal"):
        out[r["source"]["url"]] = "legal:" + r["id"]
    for t in load("tools")["tools"]:
        out[t["url"]] = "tool:" + t["id"]
    return out


def check(url):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0 (link check; qassas)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return url, r.status, ""
    except urllib.error.HTTPError as e:
        return url, e.code, ""
    except Exception as e:  # network refusals, TLS and timeouts are reported, not fatal
        return url, None, type(e).__name__


def main():
    targets = urls()
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(check, sorted(targets)))
    dead = [(u, s) for u, s, _ in results if s in (404, 410)]
    unsure = [(u, s, e) for u, s, e in results if s is None or (s >= 400 and s not in (404, 410))]
    ok = len(results) - len(dead) - len(unsure)
    for u, s in dead:
        print("DEAD %s %s (%s)" % (s, u, targets[u]))
    for u, s, e in unsure:
        print("CHECK BY HAND %s %s (%s)" % (s or e, u, targets[u]))
    print("links: %d ok, %d to check by hand, %d dead" % (ok, len(unsure), len(dead)))
    sys.exit(1 if dead else 0)


if __name__ == "__main__":
    main()
