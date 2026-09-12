#!/usr/bin/env python3
"""Check that Swift decodes each agent field as the *type* the agent sends.

`check-wire-contract.py` proves every field the agent emits is named by a Swift
model. That is not enough: `query_start` was named correctly and declared
`String?` while the agent sends epoch seconds as a number. Five of the six rows
in the fixture were null, so nothing noticed until the suite ran on a Mac.

This closes that gap. For each captured fixture it finds the Swift struct whose
`CodingKeys` best cover the object, then compares the JSON value's type against
the declared Swift type — for every row, so a nullable field that is null in the
first few rows is still checked against the row that has a value.

Run:  python3 scripts/check-wire-types.py [--verbose]
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "macos" / "fixtures"
MODELS = REPO / "macos" / "ServerOS" / "Kit" / "Domain" / "AgentModels.swift"

# Swift type -> the JSON types that may legally decode into it.
ACCEPTS: dict[str, set[str]] = {
    "String": {"str"},
    "Bool": {"bool"},
    "Int": {"int"}, "Int32": {"int"}, "Int64": {"int"}, "UInt32": {"int"}, "UInt64": {"int"},
    # JSON makes no distinction between 1 and 1.0, so a whole number is a
    # legitimate encoding of a Double and must be accepted.
    "Double": {"int", "float"}, "Float": {"int", "float"},
}

STRUCT_RE = re.compile(
    r"public struct (?P<name>\w+)\s*:[^{]*\{(?P<body>.*?)\n\}", re.S
)
PROP_RE = re.compile(
    r"^\s*public let (?P<prop>\w+)\s*:\s*(?P<type>[\w<>\[\]\., ?]+?)\s*$", re.M
)
KEYS_RE = re.compile(
    r"enum CodingKeys\s*:\s*String\s*,\s*CodingKey\s*\{(?P<body>.*?)\n\s*\}", re.S
)


def json_kind(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "array"
    return "object"


def parse_models() -> dict[str, dict[str, str]]:
    """struct name -> {json key: swift type}."""
    text = MODELS.read_text(encoding="utf-8")
    out: dict[str, dict[str, str]] = {}

    for m in STRUCT_RE.finditer(text):
        name, body = m.group("name"), m.group("body")
        props = {p.group("prop"): p.group("type").strip() for p in PROP_RE.finditer(body)}
        if not props:
            continue

        # Default: the JSON key is the property name. An explicit CodingKeys
        # enum overrides that, one case at a time.
        mapping = {prop: typ for prop, typ in props.items()}
        keys = KEYS_RE.search(body)
        if keys:
            mapping = {}
            for raw in keys.group("body").split("\n"):
                raw = raw.split("//")[0].strip()
                if not raw.startswith("case "):
                    continue
                for part in raw[len("case "):].split(","):
                    part = part.strip()
                    if not part:
                        continue
                    if "=" in part:
                        prop, json_key = (s.strip().strip('"') for s in part.split("=", 1))
                    else:
                        prop = json_key = part
                    if prop in props:
                        mapping[json_key] = props[prop]
        out[name] = mapping
    return out


def objects_in(node, into: list[dict]) -> None:
    if isinstance(node, dict):
        into.append(node)
        for v in node.values():
            objects_in(v, into)
    elif isinstance(node, list):
        for v in node:
            objects_in(v, into)


def base_type(swift: str) -> tuple[str, bool]:
    """Strip Optional and container syntax. Returns (element type, optional)."""
    t = swift.strip()
    optional = t.endswith("?")
    t = t.rstrip("?").strip()
    if t.startswith("[") and t.endswith("]") and ":" not in t:
        t = t[1:-1].strip().rstrip("?").strip()
    return t, optional


def main() -> int:
    verbose = "--verbose" in sys.argv
    models = parse_models()
    if not models:
        print("No models parsed — check the path to AgentModels.swift.", file=sys.stderr)
        return 1

    # json key -> {swift type} across every model that names it.
    by_key: dict[str, set[str]] = defaultdict(set)
    for mapping in models.values():
        for key, typ in mapping.items():
            by_key[key].add(typ)

    problems: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    files = sorted(FIXTURES.glob("*.json"))

    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"FAIL: {path.name} is not valid JSON: {exc}")
            return 1

        objects: list[dict] = []
        objects_in(data, objects)

        for obj in objects:
            for key, value in obj.items():
                declared = by_key.get(key)
                if not declared:
                    continue  # naming is check-wire-contract.py's job

                kind = json_kind(value)
                if kind in ("null", "array", "object"):
                    # Containers and null are structural; a null against a
                    # non-optional is caught below.
                    if kind == "null" and all(not base_type(d)[1] for d in declared):
                        problems[(key, "null", "non-optional " + "/".join(sorted(declared)))].add(path.name)
                    continue

                ok = False
                for d in declared:
                    elem, _ = base_type(d)
                    allowed = ACCEPTS.get(elem)
                    if allowed is None:      # a nested model or enum — not ours to judge
                        ok = True
                        break
                    if kind in allowed:
                        ok = True
                        break
                if not ok:
                    problems[(key, kind, "/".join(sorted(declared)))].add(path.name)

    if verbose:
        print(f"Checked {len(files)} fixtures against {len(models)} Swift models "
              f"({len(by_key)} distinct JSON keys).")

    if problems:
        print(f"MISMATCH — {len(problems)} field(s) decode as the wrong type:\n")
        for (key, kind, declared), where in sorted(problems.items()):
            files_txt = ", ".join(sorted(where)[:3])
            print(f"  {key}: agent sends {kind}, Swift declares {declared}")
            print(f"      seen in {files_txt}")
        print(f"\nFAIL: {len(problems)} type mismatch(es) between the agent and the Swift models.")
        return 1

    print("OK: every agent field decodes as the type the Swift model declares.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
