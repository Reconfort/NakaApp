#!/usr/bin/env python3
"""Enforce the two product rules a compiler cannot.

**Secrets never reach a log.** Passwords, private keys, request tokens, the
agent's shared secret, database passwords and container environment values are
not written to stdout, stderr, a log file, a crash report or a debug dump, in
any of the three languages.

**Demo data never reaches real mode.** A server that is not a demo server shows
what its agent actually returned, or it shows an error. It never falls back to
invented data, and the demo fixtures are not reachable from the real path.

Both are properties of the source, so both can be checked without building.
Neither is a substitute for reading the code; they are a tripwire for the
edit that reintroduces the problem six months from now.

Run:  python3 scripts/check-safety.py [--verbose]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# 1. Secrets must not be logged
# --------------------------------------------------------------------------

# Calls that put text somewhere a human or a file can read it.
LOG_CALLS = re.compile(
    r"\b("
    r"print|debugPrint|dump|NSLog|os_log"                      # Swift
    r"|println!|eprintln!|dbg!"                                # Rust
    r"|log(?:ging)?::(?:info|warn|error|debug)(?:_with)?"      # Rust, ours
    r"|console\.(?:log|warn|error|debug|info|trace)"           # TypeScript
    r"|logger\.(?:log|warn|error|debug|verbose)"               # NestJS
    r")\s*\("
)

# Identifiers that name secret material. Deliberately narrow: a checker that
# cries wolf gets switched off, and the cost of a miss here is bounded by the
# fact that this is a second line of defence, not the first.
SECRET_NAME = re.compile(
    r"\b\w*("
    r"password|passwd|passphrase"
    r"|secret|private_?key|privateKey"
    r"|api_?key|apiKey|auth_?token|authToken|bearer"
    r"|credential|shared_?key|sharedKey"
    r"|agent_?key|agentKey"
    r")\w*\b",
    re.I,
)

# Names that contain a secret word but hold no secret. Each is here because it
# appears in the tree and is safe; adding to this list is a deliberate act.
SECRET_NAME_ALLOWED = {
    # booleans and metadata *about* a secret, never the secret
    "has_password", "haspassword", "password_set", "passwordset",
    "requires_password", "requirespassword", "password_hash_present",
    "token_type", "tokentype", "credential_kind", "credentialkind",
    "credential_type", "credentialtype", "has_credential", "hascredential",
    "secret_masked", "secretmasked", "api_key_masked",
    # type and function names that appear in messages, not values
    "credentialstore", "credentialerror", "servercredential",
    "keychainerror", "tokenerror", "tokenminter", "agenttokenminter",
    "privatekeyparseerror", "passwordauthenticationunavailable",
}

# A line that says it is masking or redacting is doing the right thing.
SAFE_LINE = re.compile(r"\b(mask|masked|redact|redacted|withheld|\*{3,}|fingerprint)\b", re.I)

SOURCE_GLOBS = [
    ("swift", "macos/ServerOS/**/*.swift"),
    ("rust", "agent/crates/**/*.rs"),
    ("ts", "control-plane/src/**/*.ts"),
]


def call_argument(text: str, open_paren: int) -> str:
    """Return the text between a call's parentheses, brace-matched."""
    depth, i, n = 0, open_paren, len(text)
    while i < n:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return text[open_paren + 1:]


def strip_comments(text: str, lang: str) -> str:
    """Blank out comments so a cautionary note is not read as a violation.

    Line structure is preserved — the reported line numbers must stay true.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_secret_logging(verbose: bool) -> list[str]:
    problems: list[str] = []
    scanned = 0

    for lang, pattern in SOURCE_GLOBS:
        for path in sorted(REPO.glob(pattern)):
            raw = path.read_text(encoding="utf-8")
            text = strip_comments(raw, lang)
            scanned += 1
            rel = path.relative_to(REPO)

            for m in LOG_CALLS.finditer(text):
                arg = call_argument(text, m.end() - 1)
                line_no = text.count("\n", 0, m.start()) + 1
                line = raw.splitlines()[line_no - 1] if line_no <= len(raw.splitlines()) else ""

                for hit in SECRET_NAME.finditer(arg):
                    name = hit.group(0)
                    if name.lower().replace("-", "_") in SECRET_NAME_ALLOWED:
                        continue
                    if SAFE_LINE.search(line) or SAFE_LINE.search(arg):
                        continue
                    problems.append(
                        f"{rel}:{line_no}: {m.group(1)}(…) mentions '{name}'\n"
                        f"        {line.strip()[:110]}"
                    )
                    break

    if verbose:
        print(f"  scanned {scanned} source files for secret-bearing log calls")
    return problems


# --------------------------------------------------------------------------
# 2. The shipping app logs nothing at all
# --------------------------------------------------------------------------

# `print` in a Mac app is not a logging strategy; it is a leak waiting to be
# written. The app currently has none, and this keeps it that way. Tests may
# print freely — they do not ship.
BARE_PRINT = re.compile(r"(?<![A-Za-z0-9_.])(print|debugPrint|dump|NSLog)\s*\(")


def check_no_app_prints(verbose: bool) -> list[str]:
    problems: list[str] = []
    app = REPO / "macos" / "ServerOS"
    count = 0
    for path in sorted(app.rglob("*.swift")):
        raw = path.read_text(encoding="utf-8")
        text = strip_comments(raw, "swift")
        count += 1
        for m in BARE_PRINT.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            lines = raw.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            problems.append(
                f"{path.relative_to(REPO)}:{line_no}: {m.group(1)}(…) in shipping code\n"
                f"        {line.strip()[:110]}"
            )
    if verbose:
        print(f"  scanned {count} app files for print/dump/NSLog")
    return problems


# --------------------------------------------------------------------------
# 3. Demo data is unreachable from the real path
# --------------------------------------------------------------------------

DEMO_SYMBOL = re.compile(r"\b(DemoEnvironment|DemoData|DemoAgentClient|DemoProfile)\b")

# Where demo symbols are legitimate:
#   Kit/Demo/                 the demo implementation itself
#   App/AppModel.swift        the one place that decides demo vs real
#   App/ServerSession.swift   the session's demo branch, chosen by AppModel
#   #Preview blocks and the  `…Preview…` host types they instantiate — Xcode
#                             canvas only, never part of a real session
DEMO_ALLOWED_FILES = {
    "macos/ServerOS/App/AppModel.swift",
    "macos/ServerOS/App/ServerSession.swift",
}
DEMO_ALLOWED_DIRS = ("macos/ServerOS/Kit/Demo/",)


def _brace_block(text: str, open_brace: int) -> int:
    depth, i = 0, open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def preview_ranges(text: str) -> list[tuple[int, int]]:
    """Character ranges that only exist for the Xcode canvas.

    That is both `#Preview { … }` blocks and the `…Preview…` host types they
    instantiate — a preview usually needs a small `@State`-holding wrapper, and
    that wrapper is where the demo client gets constructed.
    """
    ranges = []
    for m in re.finditer(r"#Preview\b[^{]*\{", text):
        start = m.end() - 1
        ranges.append((m.start(), _brace_block(text, start)))

    for m in re.finditer(
        r"^[ \t]*(?:(?:public|internal|private|fileprivate)[ \t]+)?"
        r"(?:final[ \t]+)?(?:struct|class|enum|extension)[ \t]+"
        r"(\w*Preview\w*)\b[^{]*\{",
        text,
        re.M,
    ):
        start = m.end() - 1
        ranges.append((m.start(), _brace_block(text, start)))

    return ranges


def check_demo_isolation(verbose: bool) -> list[str]:
    problems: list[str] = []
    app = REPO / "macos" / "ServerOS"
    allowed_hits = 0

    for path in sorted(app.rglob("*.swift")):
        rel = str(path.relative_to(REPO))
        if rel in DEMO_ALLOWED_FILES or any(rel.startswith(d) for d in DEMO_ALLOWED_DIRS):
            continue

        raw = path.read_text(encoding="utf-8")
        text = strip_comments(raw, "swift")
        previews = preview_ranges(text)

        for m in DEMO_SYMBOL.finditer(text):
            if any(lo <= m.start() <= hi for lo, hi in previews):
                allowed_hits += 1
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            lines = raw.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            problems.append(
                f"{rel}:{line_no}: {m.group(1)} outside Kit/Demo, AppModel and #Preview\n"
                f"        {line.strip()[:110]}"
            )

    if verbose:
        print(f"  {allowed_hits} demo references inside #Preview blocks (fine)")
    return problems


# --------------------------------------------------------------------------
# 4. No credential is persisted next to the server record
# --------------------------------------------------------------------------

CRED_FIELD = re.compile(
    r"\bvar\s+\w*(password|passphrase|privateKey|secret|token)\w*\s*:", re.I
)


def check_no_persisted_credential(verbose: bool) -> list[str]:
    """SwiftData models must carry no secret. The Keychain holds those."""
    problems: list[str] = []
    checked = 0
    for path in sorted((REPO / "macos" / "ServerOS").rglob("*.swift")):
        raw = path.read_text(encoding="utf-8")
        text = strip_comments(raw, "swift")
        if "@Model" not in text:
            continue
        for m in re.finditer(r"@Model\b", text):
            start = text.find("{", m.end())
            if start == -1:
                continue
            depth, i = 0, start
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = text[start:i]
            checked += 1
            for f in CRED_FIELD.finditer(body):
                line_no = text.count("\n", 0, start + f.start()) + 1
                problems.append(
                    f"{path.relative_to(REPO)}:{line_no}: @Model stores "
                    f"'{f.group(0).strip().rstrip(':')}' — secrets belong in the Keychain"
                )
    if verbose:
        print(f"  inspected {checked} SwiftData @Model type(s)")
    return problems


# --------------------------------------------------------------------------

CHECKS = [
    ("Secrets are never passed to a log call", check_secret_logging),
    ("The shipping app has no print/dump/NSLog", check_no_app_prints),
    ("Demo data is unreachable from the real path", check_demo_isolation),
    ("No SwiftData model stores a credential", check_no_persisted_credential),
]


def main() -> int:
    verbose = "--verbose" in sys.argv
    failed = 0

    for title, fn in CHECKS:
        problems = fn(verbose)
        if problems:
            failed += 1
            print(f"FAIL — {title}: {len(problems)} problem(s)")
            for p in problems[:12]:
                print(f"    {p}")
            if len(problems) > 12:
                print(f"    … and {len(problems) - 12} more")
            print()
        else:
            print(f"OK   — {title}")

    if failed:
        print(f"\nFAIL: {failed} of {len(CHECKS)} safety checks failed.")
        return 1
    print("\nOK: secrets stay out of logs, and demo data stays out of real mode.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
