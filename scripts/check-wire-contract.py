#!/usr/bin/env python3
"""Cross-check the Swift wire models against real agent responses.

The macOS app cannot be compiled in every environment where this repo is
checked out, and a mistyped `CodingKey` is invisible to the compiler anyway — it
produces a runtime decode failure on a user's screen, months later, on the one
field nobody exercised.

So this script does what the compiler cannot: it reads every `CodingKeys` enum
out of the Swift sources, reads the JSON captured from a live agent in
`macos/fixtures/`, and reports the two ways they can disagree.

    MISSING  a key the agent sends that no Swift model names
             -> the app silently drops a field

    UNKNOWN  a key a Swift model names that no fixture contains
             -> probably a typo, or a field the fixtures do not cover

Run it from anywhere:

    python3 scripts/check-wire-contract.py [--strict]

`--strict` makes UNKNOWN keys an error too. By default only MISSING keys fail,
because some models legitimately describe endpoints the fixtures do not capture
(streaming frames, error shapes from subsystems this host lacks).

Regenerate the fixtures with `scripts/capture-fixtures.sh` against a running
agent whenever the API changes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SWIFT_ROOT = REPO / "macos" / "ServerOS"
FIXTURE_ROOT = REPO / "macos" / "fixtures"

# Keys that appear in fixtures but are deliberately not modelled, with the
# reason. Anything added here needs a justification a reviewer can check.
IGNORED_FIXTURE_KEYS: dict[str, str] = {
    # `labels` and `metadata` are free-form maps whose keys come from the user's
    # own Docker labels; their contents are not part of our contract.
    "com.docker.compose.project": "user-defined Docker label",
    "com.docker.compose.service": "user-defined Docker label",
    "com.docker.compose.project.working_dir": "user-defined Docker label",
    "com.docker.compose.config-hash": "user-defined Docker label",
    "com.docker.compose.container-number": "user-defined Docker label",
    "com.docker.compose.oneoff": "user-defined Docker label",
    "com.docker.compose.version": "user-defined Docker label",
    "desktop.docker.io/binds/0/Source": "user-defined Docker label",
    "org.opencontainers.image.version": "user-defined Docker label",
    "maintainer": "user-defined Docker label",
}

CODING_KEYS_RE = re.compile(
    r"enum\s+CodingKeys\s*:\s*String\s*,\s*CodingKey\s*\{(.*?)\n\s*\}",
    re.DOTALL,
)
CASE_RE = re.compile(r"case\s+(.+?)(?:\n|$)")
# A Decodable type with no CodingKeys enum uses its property names verbatim, so
# those are part of the contract too and must be collected.
PROPERTY_RE = re.compile(r"^\s*(?:public\s+)?(?:let|var)\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s*:")


def swift_coding_keys() -> dict[str, set[str]]:
    """Map each Swift file to the set of JSON keys its CodingKeys enums name."""
    found: dict[str, set[str]] = {}
    for path in sorted(SWIFT_ROOT.rglob("*.swift")):
        text = path.read_text(encoding="utf-8")
        keys: set[str] = set()
        for block in CODING_KEYS_RE.findall(text):
            for line in block.splitlines():
                line = line.strip()
                if not line.startswith("case "):
                    continue
                body = line[5:].split("//")[0].strip()
                # `case a, b, c` and `case a = "a_b"` may both appear, and a
                # single line can mix them: `case name, isText = "is_text"`.
                for part in split_cases(body):
                    part = part.strip()
                    if not part:
                        continue
                    if "=" in part:
                        raw = part.split("=", 1)[1].strip().strip('"')
                        keys.add(raw)
                    else:
                        keys.add(part.strip("`").strip())
        for line in text.splitlines():
            m = PROPERTY_RE.match(line)
            if m:
                # Computed properties are not decoded, so skip anything whose
                # declaration opens a `{ ... }` body on the same line.
                if "{" in line.split(":", 1)[1]:
                    continue
                keys.add(m.group(1))
        if keys:
            found[str(path.relative_to(REPO))] = keys
    return found


def split_cases(body: str) -> list[str]:
    """Split a `case` line on commas that are not inside a string literal."""
    parts, current, in_string = [], [], False
    for ch in body:
        if ch == '"':
            in_string = not in_string
            current.append(ch)
        elif ch == "," and not in_string:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def fixture_keys() -> dict[str, set[str]]:
    """Map each fixture file to every object key appearing anywhere inside it."""
    found: dict[str, set[str]] = {}
    if not FIXTURE_ROOT.exists():
        return found
    for path in sorted(FIXTURE_ROOT.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"  ! {path.name} is not valid JSON: {exc}", file=sys.stderr)
            continue
        keys: set[str] = set()
        collect(data, keys)
        found[path.name] = keys
    return found


def collect(node, into: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            into.add(key)
            collect(value, into)
    elif isinstance(node, list):
        for item in node:
            collect(item, into)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true",
                        help="treat unmatched Swift keys as errors too")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    swift = swift_coding_keys()
    fixtures = fixture_keys()

    if not swift:
        print("No CodingKeys found under macos/ServerOS — nothing to check.", file=sys.stderr)
        return 1
    if not fixtures:
        print("No fixtures under macos/fixtures — run scripts/capture-fixtures.sh first.",
              file=sys.stderr)
        return 1

    all_swift_keys: set[str] = set()
    for keys in swift.values():
        all_swift_keys |= keys

    all_fixture_keys: set[str] = set()
    for keys in fixtures.values():
        all_fixture_keys |= keys

    missing = sorted(
        k for k in all_fixture_keys - all_swift_keys if k not in IGNORED_FIXTURE_KEYS
    )
    # A type with an explicit CodingKeys enum also contributes its camelCase
    # property names, which are not wire keys. Drop any camelCase name whose
    # snake_case form is already accounted for.
    def snake(name: str) -> str:
        out = []
        for i, ch in enumerate(name):
            if ch.isupper() and i > 0:
                out.append("_")
            out.append(ch.lower())
        return "".join(out)

    unknown = sorted(
        k for k in all_swift_keys - all_fixture_keys
        if snake(k) not in all_fixture_keys and snake(k) not in all_swift_keys | {k}
        or (snake(k) == k and k not in all_fixture_keys)
    )
    unknown = sorted(
        k for k in unknown
        if snake(k) not in all_fixture_keys
    )

    if not args.quiet:
        print(f"Swift models:  {len(swift)} files, {len(all_swift_keys)} distinct JSON keys")
        print(f"Fixtures:      {len(fixtures)} files, {len(all_fixture_keys)} distinct JSON keys")
        print()

    if missing:
        print(f"MISSING — the agent sends these, no Swift model names them ({len(missing)}):")
        for key in missing:
            where = sorted(n for n, ks in fixtures.items() if key in ks)[:3]
            print(f"  {key:<34} seen in {', '.join(where)}")
        print()

    if unknown and (args.strict or not args.quiet):
        print(f"UNMATCHED — named in Swift, absent from every fixture ({len(unknown)}):")
        for key in unknown:
            where = sorted(n for n, ks in swift.items() if key in ks)[:2]
            print(f"  {key:<34} declared in {', '.join(Path(w).name for w in where)}")
        print()

    if missing:
        print(f"FAIL: {len(missing)} agent field(s) the app would silently drop.")
        return 1
    if unknown and args.strict:
        print(f"FAIL: {len(unknown)} Swift key(s) match nothing the agent sends.")
        return 1

    print("OK: every field the agent sends is named by a Swift model.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
