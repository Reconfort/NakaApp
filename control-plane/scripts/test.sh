#!/usr/bin/env bash
# Runs the pure-logic test suite.
#
# The suite is deliberately runnable with zero installed dependencies: every
# *.test.ts file imports only `node:test`, `node:assert/strict` and the
# *.logic.ts module under test. `tsx` strips the types and hands the result to
# Node's built-in test runner.
#
# `tsx` is resolved from node_modules first, then from PATH, so this works both
# in a normal checkout and in an environment where tsx is only installed
# globally.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x "node_modules/.bin/tsx" ]; then
  TSX="node_modules/.bin/tsx"
elif command -v tsx >/dev/null 2>&1; then
  TSX="$(command -v tsx)"
else
  echo "tsx not found. Run 'npm install', or install it globally: npm i -g tsx" >&2
  exit 1
fi

# `find` rather than a shell glob: `src/**/*.test.ts` needs globstar, which is
# not on by default in every bash invocation and is absent in sh.
mapfile -t TEST_FILES < <(find src -name '*.test.ts' -type f | sort)

if [ "${#TEST_FILES[@]}" -eq 0 ]; then
  echo "No test files found under src/." >&2
  exit 1
fi

exec "$TSX" --test "${TEST_FILES[@]}"
