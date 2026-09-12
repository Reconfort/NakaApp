#!/usr/bin/env python3
"""Generate `InstallScriptEmbedded.swift` from `install-agent.sh`.

The installer is a real shell script on disk, because a 400-line installer
embedded in a Swift string literal is unreviewable, unlintable, and impossible
to run by hand against a test VM — and running it by hand is how it gets
debugged.

But shipping it as a bundle resource means trusting Xcode to copy a `.sh` out of
a folder-synchronized group into the Resources phase, and a missing resource
fails at *runtime*, in front of a user who is halfway through adding a server.

So: the script stays the single source of truth, and this generates a Swift
constant from it. `InstallScript.load` prefers the bundled file and falls back to
the constant, so the feature works either way. `--check` fails if the two have
drifted, which is what keeps the fallback honest.

Run:    python3 scripts/embed-install-script.py
Check:  python3 scripts/embed-install-script.py --check
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "macos" / "ServerOS" / "Kit" / "SSH" / "Resources" / "install-agent.sh"
OUTPUT = REPO / "macos" / "ServerOS" / "Kit" / "SSH" / "InstallScriptEmbedded.swift"

HEADER = '''//  InstallScriptEmbedded.swift
//  ServerOS
//
//  GENERATED FILE — DO NOT EDIT.
//
//  Produced from `Kit/SSH/Resources/install-agent.sh` by
//  `scripts/embed-install-script.py`. Edit the shell script, then re-run that.
//
//  Why this exists: the installer ships as a bundle resource, and a resource
//  that fails to be copied fails at runtime, in front of a user who is halfway
//  through adding a server. This is the fallback that turns "ServerOS is
//  missing its installer" into "it worked anyway". `scripts/check-all.sh`
//  fails if this file and the script have drifted apart.

import Foundation

extension InstallScript {

    /// SHA-256 of the script this constant was generated from, so a mismatch
    /// is detectable rather than mysterious.
    static let embeddedChecksum = "%CHECKSUM%"

    /// The installer, compiled into the binary.
    ///
    /// Used only when the bundled resource cannot be found.
    static let embedded: String = """
%SCRIPT%
"""
}
'''


def escape(script: str) -> str:
    """Make the script safe inside a Swift multi-line string literal.

    Only two sequences matter: a backslash, and the triple-quote that would end
    the literal early. Both are escaped; the installer contains neither today,
    but a future edit might.
    """
    out = script.replace("\\", "\\\\")
    out = out.replace('"""', '\\"\\"\\"')
    return out


def main() -> int:
    check_only = "--check" in sys.argv

    if not SOURCE.is_file():
        print(f"error: {SOURCE} not found", file=sys.stderr)
        return 1

    script = SOURCE.read_text(encoding="utf-8")
    checksum = hashlib.sha256(script.encode()).hexdigest()
    generated = HEADER.replace("%CHECKSUM%", checksum).replace("%SCRIPT%", escape(script))

    if check_only:
        if not OUTPUT.is_file():
            print(f"FAIL: {OUTPUT.relative_to(REPO)} has not been generated.")
            return 1
        if OUTPUT.read_text(encoding="utf-8") != generated:
            print("FAIL: install-agent.sh and its embedded copy have drifted.")
            print("      Run: python3 scripts/embed-install-script.py")
            return 1
        print(f"OK: embedded installer matches install-agent.sh ({checksum[:12]}…)")
        return 0

    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO)}")
    print(f"  from {SOURCE.relative_to(REPO)} ({len(script.splitlines())} lines)")
    print(f"  sha256 {checksum[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
