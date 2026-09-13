#!/bin/bash
# Build ServerOS and run the build you just made.
#
# Double-click this, or run it from Terminal. It does three things in the one
# order that is always correct:
#
#   1. build
#   2. quit any ServerOS that is already running
#   3. launch the app that was just built
#
# Step 2 is the one that matters. `open Foo.app` on an app that is already
# running does not relaunch it — it brings the existing process to the front.
# So after a rebuild you are still looking at the old binary, the fix you just
# made appears not to work, and the next hour goes into debugging something
# that was already fixed. That happened repeatedly; hence this file.

set -uo pipefail
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
APP="$ROOT/.derived/Build/Products/Debug/ServerOS.app"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild not found. Install Xcode, then:  sudo xcode-select -s /Applications/Xcode.app"
  read -r -p "Press Return to close."
  exit 1
fi

echo "Building…"
if ! xcodebuild \
      -project "$ROOT/macos/ServerOS.xcodeproj" \
      -scheme ServerOS \
      -configuration Debug \
      -destination 'platform=macOS' \
      -derivedDataPath "$ROOT/.derived" \
      CODE_SIGN_IDENTITY=- \
      CODE_SIGNING_REQUIRED=NO \
      -skipPackagePluginValidation \
      build > "$ROOT/build.log" 2>&1; then
  echo
  echo "Build failed. The diagnostics:"
  echo
  grep -E "error:" "$ROOT/build.log" | sed 's|'"$ROOT"'/||' | sed 's/^ *//' | sort -u | head -40
  echo
  echo "Full output: build.log"
  read -r -p "Press Return to close."
  exit 1
fi

# Quit the old instance and wait for it to actually go. `osascript` asks
# politely first so the app can save; `pkill` is the fallback for a hung one.
if pgrep -x ServerOS >/dev/null 2>&1; then
  echo "Quitting the running ServerOS…"
  osascript -e 'quit app "ServerOS"' >/dev/null 2>&1
  for _ in $(seq 1 20); do
    pgrep -x ServerOS >/dev/null 2>&1 || break
    sleep 0.25
  done
  pgrep -x ServerOS >/dev/null 2>&1 && pkill -x ServerOS
  sleep 0.5
fi

echo "Launching the build from $(date -r "$APP/Contents/MacOS/ServerOS" '+%H:%M:%S')…"
open "$APP"
echo "Done."
