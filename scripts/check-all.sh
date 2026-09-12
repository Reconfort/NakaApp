#!/usr/bin/env bash
# Every check that can run without a Mac. Run before pushing.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

echo "=== Rust agent: build + tests ==============================="
(cd agent && cargo test --offline --workspace 2>&1 | grep -E "^test result|^error|warning: unused" | tail -20) || fail=1

echo
echo "=== Control plane: logic tests =============================="
if [ -f control-plane/scripts/test.sh ]; then
  (cd control-plane && bash scripts/test.sh 2>&1 | tail -6) || fail=1
else
  echo "  (skipped: scripts/test.sh not present)"
fi

echo
echo "=== Swift: structure and contracts ========================="
python3 scripts/check-swift.py | tail -6 || fail=1

echo
echo "=== Swift: member resolution ==============================="
python3 scripts/check-members.py | tail -4 || fail=1

echo
echo "=== Installer: script vs embedded copy ====================="
python3 scripts/embed-install-script.py --check || fail=1

echo
echo "=== Swift ↔ agent wire contract ============================"
python3 scripts/check-wire-contract.py --quiet | tail -3 || fail=1

echo
echo "=== Swift ↔ agent wire types =========================="
python3 scripts/check-wire-types.py | tail -3 || fail=1

echo
echo "=== Safety: secrets in logs, demo vs real =================="
python3 scripts/check-safety.py | tail -6 || fail=1

echo
echo "=== MVP workflow against a live agent ======================"
# The only check here that exercises the real path end to end. It needs an
# agent actually running, so it is skipped rather than failed when there is
# none — a missing agent is a missing test environment, not a broken build.
AGENT_URL="${SERVEROS_AGENT_URL:-http://127.0.0.1:18723}"
AGENT_KEY="${SERVEROS_AGENT_KEY:-/etc/serveros/agent.key}"
if curl -fsS -m 3 "$AGENT_URL/v1/health" >/dev/null 2>&1 && [ -r "$AGENT_KEY" ]; then
  python3 scripts/mvp-workflow.py --url "$AGENT_URL" --key "$AGENT_KEY" | tail -4 || fail=1
else
  echo "  (skipped: no agent reachable at $AGENT_URL, or $AGENT_KEY unreadable)"
  echo "   set SERVEROS_AGENT_URL / SERVEROS_AGENT_KEY to point at one"
fi

echo
if [ $fail -eq 0 ]; then echo "ALL OFF-MAC CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $fail
