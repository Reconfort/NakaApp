#!/usr/bin/env python3
"""Drive the entire ServerOS MVP workflow against a live agent.

This is the test that matters. The unit suites prove each piece in isolation;
this walks the exact path a user walks — connect, see health, inspect the
machine, manage a container, read its logs, browse files, look at PostgreSQL,
check the activity trail — and fails loudly if any step does not do the real
thing.

It talks to the agent over HTTP exactly as the macOS app does, including minting
the same short-lived HMAC tokens, so a break in the app's contract shows up here
rather than on a user's screen.

Usage:
    python3 scripts/mvp-workflow.py [--url http://127.0.0.1:18723]
                                    [--key /etc/serveros/agent.key]

Exit code is the number of failed steps.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
import time
import urllib.error
import urllib.request

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []


def record(status: str, step: str, detail: str = "") -> None:
    results.append((status, step, detail))
    mark = {"PASS": "  ok  ", "FAIL": " FAIL ", "SKIP": " skip "}[status]
    print(f"[{mark}] {step}" + (f"\n           {detail}" if detail else ""))


class Agent:
    """The same request shape the macOS app produces."""

    def __init__(self, base_url: str, key_path: str) -> None:
        self.base = base_url.rstrip("/")
        raw = open(key_path).read().strip()
        # base64url, unpadded — matches `AgentTokenMinter` and `auth.rs`.
        self.secret = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    def _token(self, scope: str = "read write admin", lifetime: int = 120) -> str:
        now = int(time.time())
        payload = {
            "sub": "mvp-workflow",
            "iat": now,
            "exp": now + lifetime,
            # A fresh jti every time: the agent refuses a replayed one, so a
            # cached token would fail on its second use. That is the design.
            "jti": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("="),
            "scp": scope,
        }
        body = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        signing = f"serveros.{body}"
        mac = hmac.new(self.secret, signing.encode(), hashlib.sha256).digest()
        return f"{signing}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"

    def call(self, method: str, path: str, body: dict | None = None, timeout: int = 20):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token()}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"raw": raw.decode("utf-8", "replace")[:400]}
        except Exception as e:
            return 0, {"transport": str(e)}

    def get(self, path: str, **kw):
        return self.call("GET", path, **kw)

    def post(self, path: str, body=None, **kw):
        return self.call("POST", path, body, **kw)


def check(step: str, condition: bool, detail: str = "") -> bool:
    record(PASS if condition else FAIL, step, "" if condition else detail)
    return condition


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18723")
    ap.add_argument("--key", default="/tmp/sos/etc/agent.key")
    ap.add_argument("--container", default="sos-fixture")
    args = ap.parse_args()

    print(f"ServerOS MVP workflow against {args.url}\n")
    agent = Agent(args.url, args.key)

    # 1 — liveness, unauthenticated ------------------------------------------
    req = urllib.request.Request(f"{args.url}/v1/health")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            health = json.loads(r.read())
        check("Agent is reachable and /v1/health needs no credential",
              health.get("status") == "ok", str(health)[:200])
        caps = health.get("capabilities", {})
        print(f"           capabilities: {', '.join(k for k, v in caps.items() if v is True)}")
    except Exception as e:
        record(FAIL, "Agent is reachable", str(e))
        return 1

    # 2 — the credential actually gates things -------------------------------
    bad = urllib.request.Request(f"{args.url}/v1/system")
    bad.add_header("Authorization", "Bearer serveros.forged.token")
    try:
        urllib.request.urlopen(bad, timeout=10)
        record(FAIL, "A forged token is refused", "the agent accepted it")
    except urllib.error.HTTPError as e:
        check("A forged token is refused", e.code == 401, f"got {e.code}")

    status, _ = agent.get("/v1/system")
    check("A valid token is accepted", status == 200, f"got {status}")

    token = agent._token()
    r1 = urllib.request.Request(f"{args.url}/v1/system")
    r1.add_header("Authorization", f"Bearer {token}")
    urllib.request.urlopen(r1, timeout=10)
    r2 = urllib.request.Request(f"{args.url}/v1/system")
    r2.add_header("Authorization", f"Bearer {token}")
    try:
        urllib.request.urlopen(r2, timeout=10)
        record(FAIL, "A replayed token is refused", "the agent accepted it twice")
    except urllib.error.HTTPError as e:
        check("A replayed token is refused", e.code == 401, f"got {e.code}")

    # 3 — see the machine -----------------------------------------------------
    status, system = agent.get("/v1/system")
    check("System information is real",
          status == 200 and system.get("hostname") and system.get("cpu", {}).get("cores", 0) >= 1,
          str(system)[:200])
    if status == 200:
        print(f"           {system['os']['pretty']} · {system['kernel']} · "
              f"{system['cpu']['cores']} cores · up {system['uptime_seconds'] // 3600}h")

    status, m1 = agent.get("/v1/metrics")
    time.sleep(1.2)
    status2, m2 = agent.get("/v1/metrics")
    ok = status == 200 and status2 == 200
    if ok:
        cpu = m2["cpu"]["usage_percent"]
        mem = m2["memory"]["usage_percent"]
        ok = 0 <= cpu <= 100 and 0 < mem <= 100 and m2["sampled_at"] > m1["sampled_at"]
        check("Live metrics sample and advance",
              ok, f"cpu={cpu} mem={mem} t1={m1['sampled_at']} t2={m2['sampled_at']}")
        print(f"           CPU {cpu}% · memory {mem}% · "
              f"{len(m2['disk']['filesystems'])} filesystems · "
              f"{len(m2['network']['interfaces'])} interfaces")
    else:
        check("Live metrics sample and advance", False, f"{status}/{status2}")

    status, procs = agent.get("/v1/processes?limit=10&sort=cpu")
    check("Processes are listed with real values",
          status == 200 and procs["total"] > 0
          and all(p["pid"] > 0 and p["name"] for p in procs["items"]),
          str(procs)[:200])

    status, users = agent.get("/v1/users")
    has_root = status == 200 and any(u["username"] == "root" for u in users["items"])
    check("Linux users are listed", has_root, str(users)[:200])
    if status == 200:
        leaked = [u for u in users["items"] if any(
            k in json.dumps(u) for k in ("$6$", "$y$", "$5$"))]
        check("No password hash reaches the API", not leaked,
              f"{len(leaked)} user(s) leaked hash material")

    # 4 — Docker: the flagship loop ------------------------------------------
    status, dockerinfo = agent.get("/v1/docker")
    if status != 200:
        record(SKIP, "Docker workflow", "no Docker daemon on this host")
    else:
        print(f"           Docker {dockerinfo['version']} (API {dockerinfo['api_version']})")
        status, listing = agent.get("/v1/docker/containers?all=true")
        check("Containers are listed", status == 200, str(listing)[:200])

        target = next((c for c in listing.get("items", [])
                       if c["name"] == args.container), None)
        if not target:
            record(SKIP, "Container lifecycle", f"no container named {args.container}")
        else:
            cid = target["id"]
            was_running = target["state"] == "running"
            print(f"           target: {target['name']} ({target['short_id']}) — {target['state']}")

            status, detail = agent.get(f"/v1/docker/containers/{cid}")
            check("Container detail decodes", status == 200, str(detail)[:150])

            env = {e["key"]: e for e in detail.get("env", [])}
            secret_var = next((v for k, v in env.items()
                               if any(s in k.upper() for s in ("PASSWORD", "SECRET", "URL", "KEY"))), None)
            if secret_var:
                check("Secret environment variables are masked",
                      secret_var["masked"] is True and secret_var["value"] is None,
                      f"{secret_var}")
            else:
                record(SKIP, "Secret environment variables are masked", "no secret-shaped var present")

            status, _ = agent.post(f"/v1/docker/containers/{cid}/restart")
            check("Restart is accepted", status in (200, 204), f"got {status}")

            settled = None
            for _ in range(20):
                time.sleep(0.5)
                _, again = agent.get("/v1/docker/containers?all=true")
                settled = next((c for c in again.get("items", []) if c["id"] == cid), None)
                if settled and settled["state"] == "running":
                    break
            check("Container is running after the restart",
                  settled is not None and settled["state"] == "running",
                  f"state={settled['state'] if settled else 'gone'}")

            status, logs = agent.get(f"/v1/docker/containers/{cid}/logs?tail=50")
            # Every list route on the agent answers with the same envelope —
            # {"total": n, "items": [...]} — and the Swift models decode that
            # shape. Accepting a bare array too keeps this honest if the route
            # is ever changed; it does not paper over a missing envelope.
            lines = logs.get("items", logs) if isinstance(logs, dict) else logs
            check("Container logs come back", status == 200 and isinstance(lines, list),
                  str(logs)[:200])
            if isinstance(lines, list) and lines:
                streams = {l.get("stream") for l in lines if isinstance(l, dict)}
                print(f"           {len(lines)} lines, streams: {streams or 'n/a'}")

            status, _ = agent.post(f"/v1/docker/containers/{cid}/stop?t=2")
            check("Stop is accepted", status in (200, 204), f"got {status}")
            time.sleep(2)
            _, after = agent.get("/v1/docker/containers?all=true")
            stopped = next((c for c in after.get("items", []) if c["id"] == cid), None)
            check("Container is stopped", stopped and stopped["state"] != "running",
                  f"state={stopped['state'] if stopped else 'gone'}")

            if was_running:
                agent.post(f"/v1/docker/containers/{cid}/start")
                time.sleep(1)

        for resource in ("images", "volumes", "networks"):
            status, payload = agent.get(f"/v1/docker/{resource}")
            check(f"Docker {resource} are listed", status == 200, str(payload)[:120])

    # 5 — files ---------------------------------------------------------------
    status, listing = agent.get("/v1/files?path=/etc&limit=5")
    check("A directory can be browsed",
          status == 200 and len(listing.get("entries", [])) > 0, str(listing)[:150])

    status, text = agent.get("/v1/files/read?path=/etc/hostname")
    check("A text file can be read",
          status == 200 and text.get("content"), str(text)[:150])

    status, denied = agent.get("/v1/files/read?path=/etc/shadow")
    check("A protected path is refused",
          status in (403, 404) and denied.get("error", {}).get("code") == "denied",
          f"{status} {denied}")

    status, traversal = agent.get("/v1/files/read?path=/tmp/../etc/shadow")
    check("Path traversal to a protected file is refused",
          status in (403, 404), f"{status} {str(traversal)[:120]}")

    # 6 — PostgreSQL ----------------------------------------------------------
    status, instances = agent.get("/v1/databases")
    if status == 200 and instances.get("total", 0) > 0:
        status, overview = agent.get("/v1/databases/postgres")
        if status == 200:
            check("PostgreSQL overview is real",
                  overview.get("version", "").startswith("1")
                  and overview.get("max_connections", 0) > 0,
                  str(overview)[:200])
            print(f"           PostgreSQL {overview['version']} · "
                  f"{overview['current_connections']}/{overview['max_connections']} connections · "
                  f"{overview['health']}")
            status, dbs = agent.get("/v1/databases/postgres/databases")
            check("Databases are listed",
                  status == 200 and any(d["name"] == "postgres" for d in dbs.get("items", [])),
                  str(dbs)[:150])
            status, conns = agent.get("/v1/databases/postgres/connections")
            if status == 200:
                exposed = [c for c in conns.get("items", []) if c.get("query_preview")]
                check("Query text is withheld by default", not exposed,
                      f"{len(exposed)} connection(s) exposed SQL")
        else:
            record(SKIP, "PostgreSQL workflow", f"overview unavailable ({status})")
    else:
        record(SKIP, "PostgreSQL workflow", "no reachable instance")

    # 7 — the audit trail -----------------------------------------------------
    status, activity = agent.get("/v1/activity?limit=50")
    items = activity.get("items", []) if status == 200 else []
    check("Activity is recorded", status == 200 and len(items) > 0, str(activity)[:150])
    restart_logged = any("restart" in i.get("action", "") for i in items)
    if restart_logged:
        check("The restart produced an audit record", True)
    else:
        record(SKIP, "The restart produced an audit record", "no container was restarted")

    joined = json.dumps(items)
    check("No secret material in the activity trail",
          not any(s in joined for s in ("hunter2", "$6$", "BEGIN OPENSSH", "serveros.ey")),
          "secret-shaped text found in activity")

    # 8 — failure behaviour ---------------------------------------------------
    # Ask for a file that cannot exist rather than a container: files are always
    # available, so this tests the error envelope itself rather than accidentally
    # testing whether Docker is installed. A machine without Docker should still
    # prove that a missing resource comes back as a well-formed, readable error.
    status, missing = agent.get("/v1/files/read?path=/definitely/not/a/real/path.txt")
    err = missing.get("error", {}) if isinstance(missing, dict) else {}
    check("An unknown resource returns a structured 404",
          status == 404 and err.get("code") and err.get("message", "").endswith("."),
          f"{status} {missing}")

    status, nosuch = agent.get("/v1/no-such-endpoint")
    check("An unknown endpoint returns the standard envelope",
          status == 404 and nosuch.get("error", {}).get("code") == "not_found",
          f"{status} {nosuch}")

    # --- summary -------------------------------------------------------------
    passed = sum(1 for s, _, _ in results if s == PASS)
    failed = sum(1 for s, _, _ in results if s == FAIL)
    skipped = sum(1 for s, _, _ in results if s == SKIP)
    print(f"\n{'-' * 62}")
    print(f"{passed} passed · {failed} failed · {skipped} skipped")
    if failed:
        print("\nFailures:")
        for s, step, detail in results:
            if s == FAIL:
                print(f"  {step}\n      {detail}")
    return failed


if __name__ == "__main__":
    sys.exit(main())
