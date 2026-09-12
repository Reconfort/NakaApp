#!/usr/bin/env python3
"""Static consistency checks for the ServerOS Swift sources.

This is not a type checker and does not pretend to be one. It catches the
specific class of mistake that shows up when a large Swift codebase is written
across many files and cannot be compiled on every machine that checks it out:

  DUPLICATE  the same top-level type declared in two files
             -> "invalid redeclaration", and the second author never knew
  UNBALANCED braces or parentheses that do not close
  UNDECLARED a type referenced in an annotation that nothing declares and that
             is not a known platform symbol
  CONTRACT   a view called with a signature nothing provides

Run:  python3 scripts/check-swift.py [--verbose]

It is intentionally conservative: it reports only what it is confident about,
because a checker that cries wolf gets ignored. Everything it reports has been
a real bug at least once.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOTS = [REPO / "macos" / "ServerOS", REPO / "macos" / "ServerOSTests"]

DECL_RE = re.compile(
    r"^(?P<indent>[ \t]*)"
    r"(?:@\w+(?:\([^)]*\))?\s+)*"
    r"(?P<access>public\s+|internal\s+|private\s+|fileprivate\s+|open\s+)?"
    r"(?:final\s+)?"
    r"(?P<kind>struct|class|enum|protocol|actor|extension|typealias)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)

# Types annotated in declarations: `let x: Foo`, `-> Foo`, `[Foo]`, `Foo?`
ANNOTATION_RE = re.compile(
    r"(?::\s*|->\s*)\[?\(?([A-Z][A-Za-z0-9_]*)", re.M
)

# Platform symbols we will never declare. Not exhaustive — just enough that the
# UNDECLARED report stays readable.
KNOWN = set("""
String Int Int8 Int16 Int32 Int64 UInt UInt8 UInt16 UInt32 UInt64 Double Float Bool
Character Data Date URL UUID Error Result Void Never Any AnyObject AnyHashable
Array Dictionary Set Optional Range ClosedRange IndexSet IndexPath
Task TaskGroup AsyncStream AsyncThrowingStream Duration TimeInterval Continuation
Sendable Codable Decodable Encodable Hashable Equatable Comparable Identifiable
CustomStringConvertible LocalizedError CaseIterable RawRepresentable
Foundation Bundle FileManager FileHandle ProcessInfo Process Pipe Host Thread
JSONDecoder JSONEncoder JSONSerialization PropertyListDecoder
NumberFormatter DateFormatter ByteCountFormatter RelativeDateTimeFormatter
NotificationCenter Notification NSError NSNumber NSString NSObject OSStatus
URLSession URLRequest URLResponse HTTPURLResponse URLComponents URLQueryItem
URLSessionWebSocketTask URLError CFAbsoluteTime CFString
SecItem SecItemAdd SecItemCopyMatching SecItemUpdate SecItemDelete
View ViewBuilder ViewModifier Text Image Button Label Toggle Picker Slider
Stepper TextField SecureField TextEditor Link Menu Divider Spacer Color Font
VStack HStack ZStack LazyVStack LazyHStack LazyVGrid LazyHGrid Grid GridRow
GridItem ScrollView ScrollViewReader ScrollViewProxy List Section Form Table
TableColumn TableColumnContent NavigationSplitView NavigationStack NavigationLink
NavigationSplitViewVisibility Group GeometryReader GeometryProxy Path Shape
Rectangle RoundedRectangle Circle Capsule Ellipse LinearGradient RadialGradient
AngularGradient Gradient Material Animation AnyTransition Transition Namespace
State Binding Environment EnvironmentObject ObservedObject StateObject
FocusState AppStorage SceneStorage Published ObservableObject
App Scene WindowGroup Settings Commands CommandMenu CommandGroup CommandsBuilder
FocusedValue FocusedValues FocusedValueKey EnvironmentKey EnvironmentValues
PreferenceKey Alignment HorizontalAlignment VerticalAlignment Edge EdgeInsets
UnitPoint Angle CGFloat CGPoint CGSize CGRect CGColor
ButtonStyle ButtonStyleConfiguration PrimitiveButtonStyle ToggleStyle
LabelStyle TextFieldStyle ListStyle MenuStyle ProgressViewStyle
ProgressView ContentUnavailableView DisclosureGroup TabView OutlineGroup
ColorScheme ColorSchemeContrast ControlSize KeyEquivalent EventModifiers
KeyPress Transferable UTType FileDocument ReferenceFileDocument
AnyView EmptyView TupleView ForEach ShapeStyle StrokeStyle
NSColor NSFont NSImage NSApplication NSWorkspace NSPasteboard NSTextView
NSAttributedString NSRange NSValue NSVisualEffectView NSAppearance NSEvent
KeyPathComparator SortOrder SortDescriptor AnyKeyPath PartialKeyPath KeyPath
Logger OSLog LAContext LAPolicy LAError
Schema ModelContainer ModelContext ModelConfiguration PersistentModel Model
Query FetchDescriptor Predicate SortDescriptor
SHA256 SHA512 HMAC SymmetricKey Curve25519 P256 P384 P521 AES ChaChaPoly
Digest MessageAuthenticationCode SharedSecret HashFunction
Channel ChannelHandler ChannelHandlerContext ChannelPipeline ChannelOptions
ChannelInboundHandler ChannelOutboundHandler ChannelDuplexHandler ChannelError
EventLoop EventLoopGroup EventLoopFuture EventLoopPromise MultiThreadedEventLoopGroup
ByteBuffer ByteBufferAllocator NIOAny SocketAddress ClientBootstrap ServerBootstrap
ChannelEvent CloseMode IOData AddressedEnvelope
NIOSSHHandler NIOSSHPrivateKey NIOSSHPublicKey SSHChannelType SSHChannelData
SSHChannelRequestEvent SSHClientConfiguration SSHConnectionRole SSHServerConfiguration
NIOSSHUserAuthenticationOffer NIOSSHClientUserAuthenticationDelegate
NIOSSHClientServerAuthenticationDelegate NIOSSHPublicKeyValidationDelegate
UserAuthSuccessEvent SSHUserAuthenticationMethods NIOSSHError
XCTestCase XCTAssert XCTAssertEqual XCTAssertTrue XCTAssertFalse XCTAssertNil
XCTAssertNotNil XCTAssertThrowsError XCTAssertNoThrow XCTestExpectation XCTSkip
Self Type Protocol Element Value Key Output Failure Iterator Body Content
Configuration Label Destination Item Items Trailing Leading Subject Input
CFTypeRef CFDictionary CharacterSet FileWrapper ProposedViewSize Subviews Layout
ReadConfiguration WriteConfiguration LayoutSubviews LayoutSubview ViewThatFits
Anchor UnitCurve Visibility ScrollBounceBehavior ContentTransition
""".split())


def scan() -> tuple[dict, dict, list]:
    """Return (declarations, per-file text, structural problems)."""
    declarations: dict[str, list[tuple[str, str]]] = defaultdict(list)
    texts: dict[Path, str] = {}
    problems: list[str] = []

    for root in ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.swift")):
            text = path.read_text(encoding="utf-8")
            texts[path] = text
            rel = str(path.relative_to(REPO))

            stripped = strip_noise(text)
            if stripped.count("{") != stripped.count("}"):
                problems.append(
                    f"{rel}: braces unbalanced "
                    f"({stripped.count('{')} open, {stripped.count('}')} close)"
                )
            if stripped.count("(") != stripped.count(")"):
                problems.append(
                    f"{rel}: parentheses unbalanced "
                    f"({stripped.count('(')} open, {stripped.count(')')} close)"
                )

            for m in DECL_RE.finditer(stripped):
                # Only top-level declarations can collide across files.
                if len(m.group("indent")) > 0:
                    continue
                kind, name = m.group("kind"), m.group("name")
                if kind == "extension":
                    continue
                # `private`/`fileprivate` at file scope is file-local, so the
                # same name in two files is legal Swift, not a redeclaration.
                access = (m.group("access") or "").strip()
                if access in ("private", "fileprivate"):
                    continue
                declarations[name].append((rel, kind))

    return declarations, texts, problems


def strip_noise(text: str) -> str:
    """Remove comments and string literals so braces inside them do not count."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch == "/" and nxt == "*":
            # Swift block comments nest.
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
                if text[i] == "\n":  # unterminated; stop rather than run away
                    break
                i += 1
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    declarations, texts, problems = scan()
    failures = 0

    print(f"Scanned {len(texts)} Swift files, "
          f"{sum(len(t.splitlines()) for t in texts.values())} lines, "
          f"{len(declarations)} top-level types.\n")

    # --- structural ---------------------------------------------------------
    if problems:
        failures += len(problems)
        print(f"STRUCTURE — {len(problems)} problem(s):")
        for p in problems:
            print(f"  {p}")
        print()

    # --- duplicates ---------------------------------------------------------
    dupes = {n: v for n, v in declarations.items() if len(v) > 1}
    if dupes:
        failures += len(dupes)
        print(f"DUPLICATE — same top-level name declared more than once ({len(dupes)}):")
        for name, places in sorted(dupes.items()):
            print(f"  {name}")
            for rel, kind in places:
                print(f"      {kind:<9} {rel}")
        print()

    # --- undeclared ---------------------------------------------------------
    declared = set(declarations) | KNOWN
    referenced: dict[str, set[str]] = defaultdict(set)
    for path, text in texts.items():
        for m in ANNOTATION_RE.finditer(strip_noise(text)):
            name = m.group(1)
            if name not in declared:
                referenced[name].add(str(path.relative_to(REPO)))

    # Nested types are declared indented and therefore not collected; filter out
    # anything that appears as `Outer.Name` somewhere, plus obvious generics.
    all_text = "\n".join(texts.values())
    unresolved = {
        n: f for n, f in referenced.items()
        if f".{n}" not in all_text and f"{n}." not in all_text and len(n) > 2
    }
    if unresolved:
        print(f"UNDECLARED — referenced in a type position, not declared here ({len(unresolved)}):")
        print("  (platform types this checker does not know about will appear here too)")
        for name, files in sorted(unresolved.items())[:40]:
            print(f"  {name:<28} {sorted(files)[0]}")
        print()

    # --- contract -----------------------------------------------------------
    # ServerDetailScreen dispatches to ten section views written by different
    # authors. A mismatch here is the single most likely way this app fails to
    # build, so it gets its own check.
    required_sections = [
        "ServerOverviewSection", "ProjectsSection", "DockerSection", "DatabasesSection",
        "ServicesSection", "UsersSection", "FilesSection", "ProcessesSection",
        "LogsSection", "TerminalSection",
    ]
    missing = [s for s in required_sections if s not in declarations]
    if missing:
        failures += len(missing)
        print(f"CONTRACT — server sections ServerDetailScreen calls but nothing declares:")
        for s in missing:
            print(f"  {s}")
        print()
    else:
        print("CONTRACT — all ten server sections are declared. OK\n")

    # Screens RootView dispatches to.
    required_screens = [
        "OverviewScreen", "ServersScreen", "FleetProjectsScreen", "FleetActivityScreen",
        "SettingsScreen", "ServerDetailScreen", "AddServerFlow", "CommandPalette",
        "Sidebar", "RootView",
    ]
    missing_screens = [s for s in required_screens if s not in declarations]
    if missing_screens:
        failures += len(missing_screens)
        print(f"CONTRACT — screens RootView calls but nothing declares:")
        for s in missing_screens:
            print(f"  {s}")
        print()
    else:
        print("CONTRACT — all ten top-level screens are declared. OK\n")

    if failures:
        print(f"FAIL: {failures} problem(s) that will stop a build.")
        return 1
    print("OK: no duplicate declarations, no unbalanced delimiters, contracts satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
