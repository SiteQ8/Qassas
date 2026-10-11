#!/usr/bin/env python3
"""Run every check before shipping. Exits non zero on the first class of failure it finds.

  1. generated site files and captions match their sources
  2. language rules across all content
  3. Python tests (toolkit, data, repository gates)
  4. browser and Python parity tests (Node)
  5. the browser test suite (when Playwright is available)
  6. external links (reported, a 404 or 410 fails)
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(label, cmd, required=True, env=None):
    print("== " + label, flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **(env or {})})
    if r.returncode != 0:
        print("PREFLIGHT FAILED at: " + label)
        if required:
            sys.exit(1)
    return r.returncode == 0


def main():
    py = sys.executable
    run("site build is current", [py, "scripts/build_site.py", "--check"])
    run("captions are current", [py, "tools/explainer/build.py", "--check"])
    run("language rules", [py, "scripts/check_lang.py"])
    run("python tests", [py, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "tests"])
    if shutil.which("node"):
        run("browser parity tests", ["node", "--test", "test/core.test.mjs"])
        module = os.environ.get("PLAYWRIGHT_MODULE") or ("/opt/npm-tools/node_modules/playwright" if os.path.isdir("/opt/npm-tools/node_modules/playwright") else "")
        if module or os.path.isdir(os.path.join(ROOT, "node_modules", "playwright")):
            run("browser test suite", ["node", "test/ui.mjs"], env={"PLAYWRIGHT_MODULE": module} if module else None)
        else:
            print("== browser test suite skipped: Playwright not installed")
    if "--offline" not in sys.argv:
        run("external links", [py, "scripts/links.py"])
    print("preflight passed")


if __name__ == "__main__":
    main()
