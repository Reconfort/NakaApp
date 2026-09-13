#!/usr/bin/env python3
"""Check the PostgreSQL inventory's emitted types against the Swift decoders,
from the agent SOURCE rather than from a captured fixture.

Why not just use check-wire-types.py? Because that reads fixtures, and a
fixture can only prove the type of a field that has a value in it. Four times
now the same bug has hidden in a field that was null in every captured row:

    query_start, state_change   (Connections) — String? vs number
    last_analyze, last_vacuum   (Tables)      — String? vs number
    valid_until                 (Roles)       — String? vs number

Every one decoded cleanly until a real server had a table that had been
vacuumed, or a role with a password expiry, and then the whole tab failed with
"expected String but found number". No fixture caught them because vacuuming is
rare and password expiries are rarer.

The agent's row projections say the type outright. `inventory.rs` builds each
object as `.set("key", helper(row, N))`, and the helper IS the JSON type:

    text(...)    -> String   (JSON string)
    int(...)     -> i64       (JSON number)
    boolean(...) -> bool      (JSON bool)

So this reads those `.set(...)` calls, maps each key to the type the agent
actually emits, finds the Swift property that decodes it, and checks the two
agree — for every field, populated or not.

Run:  python3 scripts/check-pg-emit-types.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVENTORY = REPO / "agent" / "crates" / "pg" / "src" / "inventory.rs"
MODELS = REPO / "macos" / "ServerOS" / "Kit" / "Domain" / "AgentModels.swift"

# Agent row helper -> the JSON type it emits.
HELPER_JSON = {"text": "string", "int": "number", "boolean": "bool"}

# JSON type -> Swift base types that may legally decode it.
JSON_ACCEPTS = {
    "string": {"String"},
    "number": {"Int", "Int8", "Int16", "Int32", "Int64",
               "UInt", "UInt8", "UInt16", "UInt32", "UInt64",
               "Double", "Float"},
    "bool": {"Bool"},
}

# `.set("key", helper(row, 3))` — only the three row helpers, because only those
# name a concrete JSON type. `.set("k", local_var)` is skipped: the overview
# object is built from locals whose types this regex can't see, and those fields
# are exercised by the fixtures anyway (they are never null).
SET_CALL = re.compile(r'\.set\(\s*"(?P<key>[^"]+)"\s*,\s*(?P<helper>text|int|boolean)\s*\(')


def agent_emitted_types() -> dict[str, str]:
    """Every key the pg inventory emits through a typed row helper -> JSON type."""
    text = INVENTORY.read_text(encoding="utf-8")
    emitted: dict[str, str] = {}
    for match in SET_CALL.finditer(text):
        key, helper = match.group("key"), match.group("helper")
        json_type = HELPER_JSON[helper]
        # If the same key is emitted two ways, that is itself a bug worth seeing.
        if key in emitted and emitted[key] != json_type:
            emitted[key] = "CONFLICT"
        else:
            emitted[key] = json_type
    return emitted


def swift_field_types() -> dict[str, str]:
    """Every `snake_case wire key -> Swift base type` across the Postgres models.

    Reads `CodingKeys` for the wire spelling and the matching stored property
    for the type. A property with no explicit CodingKey uses its own name as
    the key (Swift's default), which is why both maps are consulted.
    """
    text = MODELS.read_text(encoding="utf-8")
    fields: dict[str, str] = {}

    for struct in re.finditer(r"public struct (\w*Postgres\w*|Postgres\w*)\s*:[^{]*\{(.*?)\n\}", text, re.S):
        body = struct.group(2)

        properties: dict[str, str] = {}
        for prop in re.finditer(r"public let (\w+)\s*:\s*([\w<>\[\]., ?]+?)\s*$", body, re.M):
            name, decl = prop.group(1), prop.group(2)
            base = decl.replace("?", "").replace("[", "").replace("]", "").strip()
            properties[name] = base

        keys = {}
        keys_block = re.search(r"enum CodingKeys[^{]*\{(.*?)\}", body, re.S)
        if keys_block:
            for line in keys_block.group(1).splitlines():
                # `case fooBar = "foo_bar"` and bare `case schema, name`
                for m in re.finditer(r'(\w+)\s*=\s*"([^"]+)"', line):
                    keys[m.group(1)] = m.group(2)
                bare = re.match(r"\s*case\s+([\w,\s]+)$", line)
                if bare and "=" not in line:
                    for name in bare.group(1).split(","):
                        name = name.strip()
                        if name:
                            keys[name] = name

        for prop, base in properties.items():
            wire = keys.get(prop, prop)
            fields[wire] = base

    return fields


def main() -> int:
    emitted = agent_emitted_types()
    swift = swift_field_types()
    problems: list[str] = []

    for key, json_type in sorted(emitted.items()):
        if json_type == "CONFLICT":
            problems.append(f"agent emits `{key}` as two different types")
            continue
        if key not in swift:
            # Not every emitted key must be decoded (some the app ignores),
            # so a missing Swift field is not this checker's concern —
            # check-wire-contract.py owns that.
            continue
        base = swift[key]
        if base not in JSON_ACCEPTS[json_type]:
            problems.append(
                f"`{key}`: agent emits a {json_type}, Swift decodes it as `{base}` "
                f"— a real value will crash the decode"
            )

    print(f"Checked {len(emitted)} typed fields the PostgreSQL inventory emits.\n")
    if problems:
        for problem in problems:
            print(f"  ✗ {problem}")
        print(f"\nFAIL: {len(problems)} field(s) where the agent's type and Swift's disagree.")
        return 1

    print("OK: every typed PostgreSQL field decodes as the type the agent emits.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
