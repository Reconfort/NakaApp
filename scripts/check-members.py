#!/usr/bin/env python3
"""Check that every `Namespace.member` reference resolves.

Most of the ServerOS UI was written against a small set of shared namespaces —
`Palette`, `Typography`, `Spacing`, `Radius`, `Motion`, `Layout`, `Formatting`,
`HealthThresholds` — plus a handful of core types. A typo in any of them is a
guaranteed compile error, and on a codebase this size there can be dozens.

The compiler would find these in a second. This finds them without one.

It resolves:
  * static members on the design-system namespaces
  * instance members on the observable models (`ServerSession`, `AppModel`,
    `NavigationModel`) via `session.x`, `model.x`, `navigation.x`
  * enum cases referenced as `Type.case`

It deliberately ignores anything it cannot resolve confidently — SwiftUI
modifiers, locals, shadowed names — because a checker that reports noise gets
switched off.

Run:  python3 scripts/check-members.py
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOTS = [REPO / "macos" / "ServerOS", REPO / "macos" / "ServerOSTests"]

# Namespaces referenced by their type name: `Palette.accent`.
STATIC_NAMESPACES = [
    "Palette", "Typography", "Spacing", "Radius", "Motion", "Layout",
    "Formatting", "HealthThresholds", "Elevation", "HealthEvaluator",
    "FuzzyMatch", "DemoEnvironment", "AgentTokenMinter", "ServerStore",
    "ServerOSKeyPair", "SSHFingerprint", "Fixtures",
]

# Instance members reached through a conventional variable name.
# Only names distinctive enough that a shadowing local is unlikely. Generic
# names like `health`, `entry` or `summary` are rebound constantly (`if let
# health = try await api.health()`) and produced nothing but noise.
INSTANCE_BINDINGS = {
    "session": "ServerSession",
    "model": "AppModel",
    "navigation": "NavigationModel",
}

MEMBER_RE = re.compile(
    r"^[ \t]*"
    r"(?:@\w+(?:\([^)]*\))?[ \t]*)*"
    r"(?:(?:public|internal|private|fileprivate|open)(?:\([a-z]+\))?[ \t]+)*"
    r"(?:static[ \t]+|class[ \t]+)?"
    r"(?:final[ \t]+)?"
    r"(?:(?:public|internal|private|fileprivate)\([a-z]+\)[ \t]+)?"
    r"(?:let|var|func|case)[ \t]+"
    r"`?(?P<name>[A-Za-z_][A-Za-z0-9_]*)`?",
    re.M,
)

CASE_LIST_RE = re.compile(r"^[ \t]*case[ \t]+(?P<names>[A-Za-z_][^\n:={(]*)", re.M)


def strip_noise(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch == "/" and nxt == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if text.startswith('"""', i):
            j = text.find('"""', i + 3)
            i = n if j == -1 else j + 3
            out.append(' ')
            continue
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\n":
                    break
                i += 1
            out.append(' ')
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def type_bodies(texts: dict[Path, str]) -> dict[str, str]:
    """Extract the source of each top-level type body, brace-matched."""
    bodies: dict[str, list[str]] = defaultdict(list)
    decl = re.compile(
        r"^[ \t]*(?:@\w+(?:\([^)]*\))?[ \t]*)*"
        r"(?:public |internal |private |fileprivate |open )?(?:final )?"
        r"(?P<kind>struct|class|enum|protocol|actor|extension)[ \t]+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        re.M,
    )
    for text in texts.values():
        s = strip_noise(text)
        for m in decl.finditer(s):
            start = s.find("{", m.end())
            if start == -1:
                continue
            depth, i = 0, start
            while i < len(s):
                if s[i] == "{":
                    depth += 1
                elif s[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            bodies[m.group("name")].append(s[start:i])
    return {name: "\n".join(parts) for name, parts in bodies.items()}


def own_bodies(path: Path, stripped: str) -> dict[str, str]:
    """Top-level type bodies declared in one file, brace-matched.

    `type_bodies` merges every file's declarations together, which is right for
    looking a member up but wrong for deciding what `Self` means here.
    """
    out: dict[str, str] = {}
    decl = re.compile(
        r"^[ \t]*(?:@\w+(?:\([^)]*\))?[ \t]*)*"
        r"(?:public |internal |private |fileprivate |open )?(?:final )?"
        r"(?:struct|class|enum|protocol|actor|extension)[ \t]+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        re.M,
    )
    for m in decl.finditer(stripped):
        start = stripped.find("{", m.end())
        if start == -1:
            continue
        depth, i = 0, start
        while i < len(stripped):
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.setdefault(m.group("name"), "")
        out[m.group("name")] += stripped[start:i]
    return out


def members_of(body: str) -> set[str]:
    names: set[str] = set()
    for m in MEMBER_RE.finditer(body):
        names.add(m.group("name"))
    # `case a, b, c` and `case a(Int), b`
    for m in CASE_LIST_RE.finditer(body):
        for part in m.group("names").split(","):
            token = part.strip().split("(")[0].strip().strip("`")
            if token and token[0].isalpha():
                names.add(token)
    return names


def main() -> int:
    texts: dict[Path, str] = {}
    for root in ROOTS:
        if root.is_dir():
            for path in sorted(root.rglob("*.swift")):
                texts[path] = path.read_text(encoding="utf-8")

    bodies = type_bodies(texts)
    known: dict[str, set[str]] = {}
    for type_name in set(STATIC_NAMESPACES) | set(INSTANCE_BINDINGS.values()):
        if type_name in bodies:
            known[type_name] = members_of(bodies[type_name])

    missing_types = [t for t in STATIC_NAMESPACES if t not in known]
    problems: dict[tuple[str, str], set[str]] = defaultdict(set)

    for path, text in texts.items():
        s = strip_noise(text)
        rel = str(path.relative_to(REPO))

        for ns in STATIC_NAMESPACES:
            if ns not in known:
                continue
            for m in re.finditer(rf"\b{ns}\.([a-z][A-Za-z0-9_]*)", s):
                member = m.group(1)
                if member not in known[ns]:
                    problems[(ns, member)].add(rel)

        # `Self.x` inside a type must name a member of that type. This is what
        # a compiler catches for free, and what it caught when a careless
        # range-based edit deleted `parseInstallOutcome` while leaving three
        # calls to it: "type 'Self' has no member 'parseInstallOutcome'".
        # Resolving it here costs one pass and saves a build.
        for type_name, body in own_bodies(path, s).items():
            if type_name not in bodies:
                continue
            members = members_of(bodies[type_name])
            for m in re.finditer(r"(?<![A-Za-z0-9_.])Self\.([a-z][A-Za-z0-9_]*)", body):
                member = m.group(1)
                if member not in members:
                    problems[(f"{type_name}.Self", member)].add(rel)

        for binding, type_name in INSTANCE_BINDINGS.items():
            if type_name not in known:
                continue
            # Skip the binding entirely in a file that declares it as another
            # type: `@State private var model = AddServerModel()` means `model.`
            # in that file has nothing to do with AppModel.
            shadow = re.search(
                rf"(?:var|let)[ \t]+{binding}[ \t]*(?::[ \t]*([A-Z][A-Za-z0-9_]*)|=[ \t]*([A-Z][A-Za-z0-9_]*)\()",
                s,
            )
            if shadow:
                bound = shadow.group(1) or shadow.group(2)
                if bound != type_name:
                    continue
            for m in re.finditer(rf"(?<![A-Za-z0-9_.]){binding}\.([a-z][A-Za-z0-9_]*)", s):
                member = m.group(1)
                if member not in known[type_name]:
                    problems[(type_name, member)].add(rel)

    print(f"Resolved {len(known)} types from {len(texts)} files.")
    if missing_types:
        print(f"  (not found, skipped: {', '.join(missing_types)})")
    print()

    if problems:
        print(f"UNRESOLVED — {len(problems)} member reference(s) with no declaration:")
        for (type_name, member), files in sorted(problems.items()):
            where = sorted(files)
            extra = f"  (+{len(where) - 2} more)" if len(where) > 2 else ""
            print(f"  {type_name}.{member}")
            for f in where[:2]:
                print(f"      {f}")
            if extra:
                print(f"     {extra}")
        print()
        print(f"FAIL: {len(problems)} unresolved member reference(s).")
        return 1

    print("OK: every checked member reference resolves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
