#!/bin/bash
# ServerOS build loop.
#
# Double-click this file (or run it in Terminal). It builds the macOS app,
# runs the test suite if the build succeeds, and then stays open. Whenever
# a `.build-request` file appears next to it, it builds again — so one run
# gives a continuous compile-and-fix loop with no further action from you.
#
# Press Control-C, or close the window, to stop.
#
# What it writes, next to this script:
#   build.log          full xcodebuild output (large)
#   build-errors.txt   just the error/warning lines (small — read this first)
#   test.log           full test output
#   build-status.txt   one-line machine-readable summary

# This script lives in scripts/, so the project root is its parent. Resolve it
# from the script's own path rather than the caller's working directory: it is
# started by a double-click on ../build.command as often as from a shell.
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
PROJ="$ROOT/macos/ServerOS.xcodeproj"
LOG="$ROOT/build.log"
ERRS="$ROOT/build-errors.txt"
TESTLOG="$ROOT/test.log"
STATUS="$ROOT/build-status.txt"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild not found."
  echo "Install Xcode from the App Store, then run:"
  echo "    sudo xcode-select -s /Applications/Xcode.app"
  echo "xcodebuild-not-found" > "$STATUS"
  read -r -p "Press Return to close."
  exit 1
fi

# Distil the parts of a build log worth reading. xcodebuild output runs to
# megabytes; the diagnostics are a few dozen lines. Anything reading this
# over a slow link wants the few dozen.
distil() {
  local src="$1" dest="$2"
  {
    echo "# $(date '+%Y-%m-%d %H:%M:%S')  —  $(basename "$src")"
    echo
    grep -E "(error|warning):" "$src" | sed 's/^ *//' | sort -u
    echo
    echo "--- package resolution ---"
    grep -iE "(unable to resolve|failed to resolve|couldn't be resolved|package .* not found|fatal:)" "$src" | sort -u | head -20
    echo
    echo "--- signing / destination ---"
    grep -iE "(does not support the requested|no such (module|file)|requires a development team|Unable to find a destination)" "$src" | sort -u | head -20
  } > "$dest"
}

summarise() {
  local rc="$1" phase="$2" src="$3"
  # `grep -c` prints 0 *and* exits 1 when there is no match, so `|| echo 0`
  # would append a second count. Assign on failure instead.
  local e w
  e=$(grep -cE "error:" "$src" 2>/dev/null) || e=0
  w=$(grep -cE "warning:" "$src" 2>/dev/null) || w=0
  echo "phase=$phase exit=$rc errors=$e warnings=$w at=$(date '+%H:%M:%S')" > "$STATUS"
  echo "  $phase: exit $rc, $e errors, $w warnings"
}

build() {
  local n="$1"
  echo "=== ServerOS build #$n  $(date '+%H:%M:%S') ===" | tee "$LOG"
  echo "phase=building exit= errors= warnings= at=$(date '+%H:%M:%S')" > "$STATUS"

  # -skipPackagePluginValidation keeps a first run from stopping on a prompt.
  # CODE_SIGNING_ALLOWED=NO keeps a machine with no signing identity from
  # failing a build that is otherwise fine — this is a Debug build for the
  # developer's own machine, not something being shipped.
  xcodebuild \
      -project "$PROJ" \
      -scheme ServerOS \
      -configuration Debug \
      -destination 'platform=macOS' \
      -derivedDataPath "$ROOT/.derived" \
      CODE_SIGNING_ALLOWED=NO \
      -skipPackagePluginValidation \
      build >> "$LOG" 2>&1
  local rc=$?
  distil "$LOG" "$ERRS"
  summarise "$rc" "build" "$LOG"
  [ $rc -ne 0 ] && return $rc

  echo "  build succeeded — running tests"
  echo "phase=testing exit= errors= warnings= at=$(date '+%H:%M:%S')" > "$STATUS"
  xcodebuild \
      -project "$PROJ" \
      -scheme ServerOS \
      -configuration Debug \
      -destination 'platform=macOS' \
      -derivedDataPath "$ROOT/.derived" \
      CODE_SIGNING_ALLOWED=NO \
      -skipPackagePluginValidation \
      test > "$TESTLOG" 2>&1
  local trc=$?
  {
    echo
    echo "--- test results ---"
    grep -E "(Test Suite '[^']*' (passed|failed)|Executed .* tests?,|\.swift:[0-9]+:([0-9]+:)? error:|XCTAssert)" \
        "$TESTLOG" | sed 's/^ *//' | tail -40
  } >> "$ERRS"
  # A test run streams the app's own os_log output, and macOS logs plenty of
  # XPC noise ("Unable to get synchronousRemoteObjectProxy…") that contains the
  # word `error:`. Counting those makes a green run look broken. Only a
  # compiler diagnostic or an XCTest failure counts, and both name a .swift
  # file and a line.
  local failed terrs skipped
  failed=$(grep -cE "^Test Case .* failed" "$TESTLOG" 2>/dev/null) || failed=0
  skipped=$(grep -cE "^Test Case .* skipped" "$TESTLOG" 2>/dev/null) || skipped=0
  terrs=$(grep -cE "\.swift:[0-9]+:([0-9]+:)? error:" "$TESTLOG" 2>/dev/null) || terrs=0
  echo "phase=tested exit=$trc errors=$terrs failed_tests=$failed skipped=$skipped at=$(date '+%H:%M:%S')" > "$STATUS"
  echo "  tests: exit $trc, $failed failing, $skipped skipped"
  if [ "$skipped" -gt 0 ] && grep -q "Keychain is not usable" "$TESTLOG" 2>/dev/null; then
    echo
    echo "  Note: the Keychain tests skipped themselves. This build passes"
    echo "  CODE_SIGNING_ALLOWED=NO so it works on a machine with no signing"
    echo "  identity, and an unsigned test host cannot reach the Keychain."
    echo "  To run them, open the project in Xcode, pick your team under"
    echo "  Signing & Capabilities, and press Cmd-U."
  fi
  return $trc
}

echo "ServerOS build loop. Leave this window open."
echo "Project: $PROJ"
echo
n=1
build "$n"
echo
echo "Waiting for the next build request…  (Control-C to stop)"
while true; do
  if [ -f "$ROOT/.build-request" ]; then
    rm -f "$ROOT/.build-request"
    n=$((n + 1))
    build "$n"
    echo
    echo "Waiting for the next build request…  (Control-C to stop)"
  fi
  sleep 2
done
