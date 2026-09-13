#!/usr/bin/env python3
"""Check that no `public` declaration exposes an internal type.

Swift refuses this outright:

    struct InstallOutcome { ... }                    // internal
    public func upgradeAgent() -> InstallOutcome     // error

    "method cannot be declared public because its result uses an
     internal type"

It is an easy mistake to make and an invisible one to read past: both halves
look fine on their own, and the file only fails to compile when they meet. It
cost a build here — `AgentBootstrap.upgradeAgent` was written public, returning
an internal `InstallOutcome`, and nothing off-Mac noticed until this existed.

What it checks
  * `public` / `open` funcs, initialisers and typed properties
  * every capitalised identifier in the signature — parameters, return type,
    generic arguments, tuple members
  * against every type the module declares, at whatever access level

What it deliberately does not check
  * members of a `public protocol`, which are implicitly public without
    saying so — worth adding when one appears
  * types from other modules, which are not in the map and so are skipped
  * a name declared twice at different access levels: flagged only when
    every declaration of that name is non-public

Run:  python3 scripts/check-access.py
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOTS = [REPO / "macos" / "ServerOS"]

ACCESS = r"(?:open|public|package|internal|fileprivate|private)"

# `public struct Foo`, `actor Bar`, `enum Baz: String`, `final class Qux`.
TYPE_RE = re.compile(
    r"^[ \t]*"
    r"(?:@\w+(?:\([^)]*\))?[ \t]+)*"
    r"(?P<access>" + ACCESS + r")?(?:\([a-z]+\))?[ \t]*"
    r"(?:final[ \t]+|indirect[ \t]+)*"
    r"(?P<kind>struct|class|enum|actor|protocol|typealias)[ \t]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

# `public func x(...) -> Y`, `public var x: Y`, `public init(...)`.
MEMBER_RE = re.compile(
    r"^[ \t]*"
    r"(?:@\w+(?:\([^)]*\))?[ \t]+)*"
    r"(?P<access>open|public)(?:\([a-z]+\))?[ \t]+"
    r"(?:static[ \t]+|class[ \t]+|final[ \t]+|convenience[ \t]+|required[ \t]+|"
    r"nonisolated[ \t]+|override[ \t]+)*"
    r"(?P<kind>func|var|let|init|subscript)\b"
    r"(?P<rest>.*)$"
)

IDENTIFIER_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\b")

# Standard library and framework types, plus anything a signature can name that
# the module does not declare. Names not in the module's own map are skipped
# anyway; this list exists only to document the intent.
GENERIC_PARAMETERS = {"T", "U", "V", "Element", "Item", "Value", "Failure"}


def type_declarations() -> dict[str, set[str]]:
    """Every type the module declares → the set of access levels it was
    declared at (usually one)."""
    declarations: dict[str, set[str]] = defaultdict(set)
    for root in ROOTS:
        for path in sorted(root.rglob("*.swift")):
            for line in path.read_text(encoding="utf-8").splitlines():
                match = TYPE_RE.match(line)
                if not match:
                    continue
                access = match.group("access") or "internal"
                declarations[match.group("name")].add(access)
    return declarations


def signature_of(kind: str, rest: str) -> str:
    """The part of a declaration that carries types.

    For a property, everything after the colon. For anything else, the
    parameter list and return type, stopping at the body.
    """
    rest = rest.split("{")[0]
    if kind in ("var", "let"):
        return rest.split(":", 1)[1] if ":" in rest else ""
    return rest


# SwiftUI style protocols. None of them is a `View`, so `@Environment`,
# `@State`, `@StateObject` and friends declared on a conforming type are never
# installed in the view graph — they read their default value once and never
# update. SwiftUI reports it at runtime and otherwise says nothing:
#
#     Accessing Environment<Bool>'s value outside of being installed on a View.
#
# It cost the design system two features silently: `\.isEnabled` defaults to
# true, so disabled buttons were painted as enabled on every screen, and the
# hover highlight on secondary buttons never ran. The body belongs in a nested
# `View`, which is where those wrappers work.
STYLE_PROTOCOLS = (
    "ButtonStyle", "PrimitiveButtonStyle", "LabelStyle", "ToggleStyle",
    "ProgressViewStyle", "MenuStyle", "GaugeStyle", "TextFieldStyle",
    "DisclosureGroupStyle", "ControlGroupStyle", "TableRowContent",
)
STYLE_DECL = re.compile(
    r"^[ \t]*(?:public\s+|internal\s+|private\s+|fileprivate\s+|open\s+)*"
    r"(?:final\s+)?(?:struct|class)\s+(\w+)\s*:\s*([^{]+)\{",
    re.MULTILINE,
)
DYNAMIC_PROPERTY = re.compile(r"^\s*@(Environment|State|StateObject|ObservedObject|FocusState|AppStorage|SceneStorage)\b")


# Names a conforming type may not reuse for a nested type.
#
# `ButtonStyle` declares `associatedtype Body`. A nested `struct Body` becomes
# the witness for it, instead of the `some View` that `makeBody` returns, and
# the compiler then reports "does not conform to protocol 'ButtonStyle'" and
# "struct 'Body' must be declared public" — two errors that name everything
# except the cause. Same for `Configuration`.
RESERVED_NESTED = {"Body", "Configuration"}
NESTED_TYPE = re.compile(r"^\s*(?:public\s+|internal\s+|private\s+|fileprivate\s+)*(?:final\s+)?(?:struct|class|enum)\s+(\w+)")


def check_styles_have_no_dynamic_properties() -> list[str]:
    """A style type must not declare a dynamic property, or shadow one of the
    protocol's associated-type names with a nested type."""
    problems: list[str] = []
    for root in ROOTS:
        for path in sorted(root.rglob("*.swift")):
            lines = path.read_text(encoding="utf-8").splitlines()
            text = "\n".join(lines)
            for match in STYLE_DECL.finditer(text):
                name, conformances = match.group(1), match.group(2)
                if not any(p in conformances for p in STYLE_PROTOCOLS):
                    continue
                if "View" in re.split(r"[,\s]+", conformances):
                    continue  # conforms to View as well; the wrappers work
                start = text.count("\n", 0, match.start())
                # Scan the declaration's own body, stopping at the first nested
                # type — a nested `View` is exactly the correct fix, and its
                # properties are not the style's.
                depth = 0
                for offset, line in enumerate(lines[start:], start=start):
                    depth += line.count("{") - line.count("}")
                    nested = NESTED_TYPE.match(line) if offset > start else None
                    if nested:
                        if nested.group(1) in RESERVED_NESTED:
                            problems.append(
                                f"{path.relative_to(REPO)}:{offset + 1}: {name} nests a type called "
                                f"`{nested.group(1)}`, which is one of the protocol's associated types — "
                                f"it becomes the witness and conformance fails\n    {line.strip()}"
                            )
                        break
                    if offset > start and DYNAMIC_PROPERTY.match(line):
                        problems.append(
                            f"{path.relative_to(REPO)}:{offset + 1}: {name} is a style, not a View — "
                            f"this wrapper reads its default forever\n    {line.strip()}"
                        )
                    if depth <= 0 and offset > start:
                        break
    return problems


def main() -> int:
    declarations = type_declarations()
    exposed = {name for name, levels in declarations.items()
               if levels & {"public", "open", "package"}}
    problems: list[str] = []

    for root in ROOTS:
        for path in sorted(root.rglob("*.swift")):
            relative = path.relative_to(REPO)
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = MEMBER_RE.match(line)
                if not match:
                    continue
                signature = signature_of(match.group("kind"), match.group("rest"))
                for identifier in IDENTIFIER_RE.findall(signature):
                    if identifier in GENERIC_PARAMETERS:
                        continue
                    if identifier not in declarations:
                        continue          # not ours: another module's type
                    if identifier in exposed:
                        continue          # declared public somewhere
                    problems.append(
                        f"{relative}:{number}: {match.group('access')} "
                        f"{match.group('kind')} exposes internal type "
                        f"`{identifier}`\n    {line.strip()}"
                    )

    style_problems = check_styles_have_no_dynamic_properties()

    print(f"Read {len(declarations)} type declarations.\n")
    if style_problems:
        for problem in style_problems:
            print(f"  ✗ {problem}")
        print(f"\nFAIL: {len(style_problems)} SwiftUI style(s) declare a dynamic property.")
        print("Styles are not Views. Move the body into a nested View struct.")
        return 1
    if problems:
        for problem in problems:
            print(f"  ✗ {problem}")
        print(f"\nFAIL: {len(problems)} public declaration(s) name an internal type.")
        print("Swift rejects these. Make the type public, or the member internal.")
        return 1

    print("OK: no public declaration exposes an internal type.")
    print("OK: no SwiftUI style declares a dynamic property.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
