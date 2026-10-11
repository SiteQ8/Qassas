"""Load the JSON data shipped inside the package."""

import json
import os

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_cache = {}


def load(name):
    if name == "curriculum" and name not in _cache:
        folder = os.path.join(DATA, "modules")
        mods = []
        for f in sorted(os.listdir(folder)):
            if f.endswith(".json"):
                with open(os.path.join(folder, f), encoding="utf-8") as fh:
                    mods.append(json.load(fh))
        _cache[name] = {"modules": mods}
    if name not in _cache:
        with open(os.path.join(DATA, name + ".json"), encoding="utf-8") as fh:
            _cache[name] = json.load(fh)
    return _cache[name]
