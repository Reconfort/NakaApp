//  DatabaseProvisioner.swift
//  ServerOS
//
//  Giving ServerOS its own read-only account on a database, so the user does
//  not have to.
//
//  ──────────────────────────────────────────────────────────────────────────
//  Why this exists
//
//  Having root on a machine does not give you access to the databases running
//  on it. PostgreSQL keeps its own accounts, and so does every other engine.
//  So the first time ServerOS connected to a real server it did the correct
//  thing and the wrong thing at once: it reported, accurately, that it could
//  see PostgreSQL but had no role to sign in as — and then told the user to
//  open a terminal and run `psql`.
//
//  That is the exact experience this product exists to remove. ServerOS is
//  already holding an authenticated root SSH connection to that machine. It
//  can create the account itself, and it should, with the user's consent and
//  in one action.
//
//  Why over SSH rather than through the agent
//
//  Creating database roles is a privilege the agent does not have and should
//  not be given. The agent is deliberately minimal — named capability routes,
//  a hardened systemd unit, no shell. Provisioning is a one-time setup act of
//  the same kind as installing the agent in the first place, so it runs the
//  same way: over the SSH connection the user already authenticated, as root,
//  with every command written out in full below rather than assembled at
//  runtime.
//
//  What it does to the database
//
//  One role, `serveros`, with LOGIN and `pg_monitor`. `pg_monitor` is
//  PostgreSQL's own built-in role for exactly this: it can read the catalogue
//  and the statistics views, and it cannot read table data. No superuser, no
//  ownership, no write access, nothing beyond what the Databases screen shows.
//
//  Why the agent is told to use 127.0.0.1 and not the socket
//
//  The first version of this created the role, set a password, restarted the
//  agent, reported success — and the screen still said "PostgreSQL rejected
//  these credentials". The reason was structural, not a typo. The agent runs
//  as **root** (it needs to, for Docker, services, files and users), it
//  connected over the Unix socket, and Debian and Ubuntu ship
//
//      local   all   all   peer
//
//  in `pg_hba.conf`. Peer authentication ignores passwords entirely and
//  matches the *operating-system* user of the connecting process against the
//  role name: `root` is not `serveros`, so it failed, and no password we could
//  set would ever have changed that.
//
//  Loopback TCP takes the `host … 127.0.0.1/32 scram-sha-256` line instead,
//  which does consult the password. That is a change to the agent's config
//  only — nothing in PostgreSQL's own configuration is touched.
//
//  And why it verifies
//
//  The same version also declared victory without checking. Everything below
//  that changes something is followed by a step that proves it: the role is
//  signed into with the password that was just set, from the server itself,
//  before the agent is ever pointed at it; and the agent is confirmed to still
//  be running after the restart. "It worked" that isn't checked isn't a
//  result, it's a hope.

import CryptoKit
import Foundation

public actor DatabaseProvisioner {

    /// What the server looks like before anything is changed.
    public struct Probe: Sendable, Equatable {
        /// `psql` is installed, so there is a client to drive.
        public var hasPsql = false
        /// A superuser connection succeeded, so the cluster is up and this
        /// account can administer it.
        public var canAdminister = false
        /// The `serveros` role already exists.
        public var roleExists = false
        /// It exists and may log in.
        public var roleCanLogin = false
        /// It is already a member of `pg_monitor`.
        public var hasMonitor = false
        /// The agent's own system account exists. It owns the password file;
        /// it is not what authenticates, since the agent runs as root.
        public var serviceUserExists = false
        /// What the administrator connection actually said when it failed.
        ///
        /// Carried because the alternative is a guess. "The cluster may be
        /// stopped, or this account may not be able to become the postgres
        /// user" was shown for a month against a running cluster, and the one
        /// line that would have identified the real cause was being thrown away
        /// by `>/dev/null 2>&1`.
        public var adminFailure = ""
        /// `listen_addresses` exactly as PostgreSQL reports it.
        public var listenAddresses = ""
        /// The port PostgreSQL is actually serving on, which is not always 5432.
        public var port = 5432

        /// Nothing to do — the role is already exactly as it should be.
        public var isAlreadyProvisioned: Bool {
            roleExists && roleCanLogin && hasMonitor
        }

        /// Whether provisioning can even be attempted.
        public var canProvision: Bool { hasPsql && canAdminister }

        /// Whether a connection to 127.0.0.1 can reach this cluster at all.
        ///
        /// `listen_addresses` is a comma-separated list; `*` means every
        /// interface. Debian and Ubuntu ship `localhost`, so this is true on a
        /// stock install — but a cluster deliberately restricted to a private
        /// interface is a real configuration, and one worth stopping for
        /// rather than failing obscurely three steps later.
        public var listensOnLoopback: Bool {
            let entries = listenAddresses
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            if entries.contains("*") { return true }
            return entries.contains { entry in
                entry == "localhost" || entry == "127.0.0.1"
                    || entry == "0.0.0.0" || entry == "::1" || entry == "::"
            }
        }
    }

    /// What actually changed.
    public struct Outcome: Sendable, Equatable {
        public var createdRole = false
        public var grantedMonitor = false
        public var setPassword = false
        public var wroteConfig = false
        public var restartedAgent = false
        /// The new role was signed into successfully, on the server, with the
        /// password that was just set. Nothing claims success without this.
        public var verified = false

        /// One sentence for the user, in the past tense, saying what happened.
        public var summary: String {
            var parts: [String] = []
            parts.append(createdRole ? "Created the serveros role" : "The serveros role was already there")
            if grantedMonitor { parts.append("granted it pg_monitor") }
            if setPassword { parts.append("gave it a password only this server holds") }
            if verified { parts.append("signed in with it to check that it works") }
            if restartedAgent { parts.append("restarted the agent") }
            return parts.joined(separator: ", ") + "."
        }
    }

    /// Where the agent keeps the password, and what owns it. The config path
    /// and service name come from `AgentBootstrap` rather than being written
    /// out again here — two copies of a path is how they come to disagree.
    static let configDirectory = "/etc/serveros"
    static let passwordPath = "/etc/serveros/postgres.pw"
    static let configPath = AgentBootstrap.agentConfigPath
    static let serviceName = AgentBootstrap.serviceName
    static let serviceUser = "serveros"
    static let roleName = "serveros"
    /// The agent connects here rather than over the Unix socket. See the note
    /// at the top of the file — with the socket, peer authentication matches
    /// the agent's OS user (root) against the role name and always fails.
    static let loopbackHost = "127.0.0.1"

    private let client: SSHClient
    private let privileged: String

    /// - Parameter privileged: `""` when already root, `"sudo -n "` otherwise.
    public init(client: SSHClient, privileged: String = "") {
        self.client = client
        self.privileged = privileged
    }

    // MARK: - Looking before touching

    /// The script that reads the server's state. Static so it can be read in a
    /// test, which is how the bug documented on `asPostgres` was closed.
    static func probeScript() -> String {
        func query(_ sql: String) -> String {
            asPostgres("psql -tAqc \(Shell.quote(sql))")
        }
        return """
        echo "psql=$(command -v psql >/dev/null 2>&1 && echo yes || echo no)"
        echo "svcuser=$(id -u \(serviceUser) >/dev/null 2>&1 && echo yes || echo no)"
        if \(query("SELECT 1")) >/dev/null 2>&1; then
            echo "admin=yes"
            echo "role=$(\(query("SELECT rolcanlogin FROM pg_roles WHERE rolname='\(roleName)'")) 2>/dev/null | tr -d '[:space:]')"
            echo "monitor=$(\(query("SELECT pg_has_role('\(roleName)','pg_monitor','member')")) 2>/dev/null | tr -d '[:space:]')"
            echo "listen=$(\(query("SHOW listen_addresses")) 2>/dev/null | tr -d '[:space:]')"
            echo "pgport=$(\(query("SHOW port")) 2>/dev/null | tr -d '[:space:]')"
        else
            echo "admin=no"
            echo "adminerr=$(\(query("SELECT 1")) 2>&1 | tr '\\n' ' ' | cut -c1-200)"
        fi
        """
    }

    /// Read the server's current state. Changes nothing.
    public func probePostgres() async throws -> Probe {
        let result = try await client.run(sudoPrefixed(Self.probeScript()), timeout: 60)
        let fields = Self.labelled(result.stdout)

        var probe = Probe()
        probe.hasPsql = fields["psql"] == "yes"
        probe.serviceUserExists = fields["svcuser"] == "yes"
        probe.canAdminister = fields["admin"] == "yes"
        // Empty means no such role; `t`/`f` means it exists and whether it can log in.
        if let role = fields["role"], !role.isEmpty {
            probe.roleExists = true
            probe.roleCanLogin = role == "t"
        }
        probe.hasMonitor = fields["monitor"] == "t"
        probe.adminFailure = fields["adminerr"] ?? ""
        probe.listenAddresses = fields["listen"] ?? ""
        // A cluster that answers `SHOW port` with something unparseable is not
        // one to guess about, but 5432 is right often enough to be a better
        // default than giving up.
        probe.port = fields["pgport"].flatMap(Int.init) ?? 5432
        return probe
    }

    // MARK: - Doing it

    /// Create the role, grant it `pg_monitor`, give it a password, point the
    /// agent at that password, and restart the agent.
    ///
    /// Idempotent: running it twice is harmless, and running it against a
    /// half-provisioned server finishes the job.
    public func provisionPostgres() async throws -> Outcome {
        let probe = try await probePostgres()

        guard probe.hasPsql else {
            throw ServerOSError.databaseProvisioningUnavailable(
                reason: "psql isn't installed on this server, so ServerOS has no way to talk to PostgreSQL."
            )
        }
        guard probe.canAdminister else {
            // Say what the server said. A list of things that "may" be wrong is
            // worth less than the one line that is.
            let detail = probe.adminFailure.trimmingCharacters(in: .whitespacesAndNewlines)
            throw ServerOSError.databaseProvisioningUnavailable(
                reason: "ServerOS couldn't sign in to PostgreSQL as an administrator on this server."
                    + (detail.isEmpty ? "" : "\n\nThe server said: \(detail)")
                    + "\n\nThis usually means the cluster is stopped, there is no postgres system account "
                    + "(PostgreSQL running in a container has none on the host), or this account can't become it."
            )
        }
        guard probe.listensOnLoopback else {
            throw ServerOSError.databaseProvisioningUnavailable(
                reason: "PostgreSQL on this server isn't listening on 127.0.0.1 — its listen_addresses is "
                    + "\"\(probe.listenAddresses)\". The agent has to sign in with a password, and PostgreSQL only "
                    + "accepts passwords over a network connection, so it needs to be reachable on the loopback "
                    + "address. Adding localhost to listen_addresses in postgresql.conf and restarting PostgreSQL "
                    + "would fix it — ServerOS won't restart your database for you."
            )
        }

        var outcome = Outcome()

        // A password the server holds and this Mac does not keep: it is written
        // to the server, verified there, and never stored on this side. There
        // is no reason for ServerOS to hold a second copy of a secret that only
        // one machine needs.
        let password = Self.generatePassword()

        // The whole statement goes in on **stdin**. A password in a command
        // line is readable by every user on the box through `ps`, which would
        // make this worse than the problem it solves.
        let sql = """
        \\set ON_ERROR_STOP on
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '\(Self.roleName)') THEN
                CREATE ROLE \(Self.roleName) LOGIN;
                RAISE NOTICE 'serveros-created-role';
            END IF;
        END
        $$;
        ALTER ROLE \(Self.roleName) LOGIN PASSWORD '\(Self.escapeSQL(password))';
        GRANT pg_monitor TO \(Self.roleName);
        """

        let applied = try await client.run(
            // `su` passes stdin straight through, which is what carries the
            // statement — and the password inside it — to psql.
            sudoPrefixed(Self.asPostgres("psql -q -f - 2>&1")),
            stdin: Data(sql.utf8),
            timeout: 120
        )
        guard applied.succeeded else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "creating the role",
                // psql echoes the statement it choked on, which would include
                // the password. Only the last line, and only when it has no
                // chance of carrying one.
                detail: Self.safeTail(applied.stdout + applied.stderr)
            )
        }
        outcome.createdRole = !probe.roleExists
        outcome.grantedMonitor = true
        outcome.setPassword = true

        // Prove the credential before anything starts depending on it. This is
        // the step whose absence produced "database access is set up" followed
        // immediately by "PostgreSQL rejected these credentials": it exercises
        // the same path the agent will take — loopback TCP, this role, this
        // password — so if pg_hba, the port or the password is wrong, it fails
        // here, with PostgreSQL's own words, and the agent's configuration is
        // left untouched.
        try await verifySignIn(password: password, port: probe.port)
        outcome.verified = true

        // The password file: `root:root`, 0600, with the value on stdin for the
        // same reason as the SQL above.
        //
        // **root**, not `serveros`. This was written as
        // `chown serveros:serveros`, on the reasonable-sounding theory that the
        // file should belong to the service account — and it produced
        // `/etc/serveros/postgres.pw: Permission denied (os error 13)` from an
        // agent running as **root**, which is a sentence that should be
        // impossible. It isn't, because the systemd unit sets
        //
        //     CapabilityBoundingSet=
        //
        // which strips CAP_DAC_OVERRIDE. Root's power to ignore file
        // permissions *is* that capability; without it, uid 0 obeys ordinary
        // DAC like anyone else, and a 0600 file owned by `serveros` is closed
        // to it. Every other file in /etc/serveros — `agent.key`,
        // `agent.json`, the directory itself at 0700 — is root-owned for
        // exactly this reason. This one broke the convention and was the only
        // file the agent couldn't read.
        //
        // The `stat` at the end is not decoration. The whole failure was
        // ownership being something other than what this code assumed, so the
        // ownership is read back and checked rather than trusted.
        let wrote = try await client.run(
            sudoPrefixed(Self.passwordFileScript()),
            stdin: Data(password.utf8),
            timeout: 60
        )
        guard wrote.succeeded else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "saving the password on the server",
                detail: Self.safeTail(wrote.stdout + wrote.stderr, hiding: password)
            )
        }

        outcome.wroteConfig = try await pointAgentAtPostgres(port: probe.port)
        outcome.restartedAgent = try await restartAgent(hiding: password)
        return outcome
    }

    // MARK: - Proving it works

    /// Sign in as the new role, from the server, the way the agent will.
    private func verifySignIn(password: String, port: Int) async throws {
        // The password arrives on **stdin** and is moved into the environment
        // by the remote shell. Writing `PGPASSWORD=… psql …` directly would
        // have put it in the command line of the shell sshd starts, where
        // every user on the machine can read it with `ps` — the same mistake
        // the SQL above goes out of its way to avoid. Read from a pipe, it
        // exists only in that shell's environment, and `/proc/<pid>/environ`
        // is readable by the process owner alone.
        //
        // Deliberately *not* `-u postgres`: the point is to prove that an
        // ordinary account can sign in with this password, because the account
        // that will be doing it is the agent's, running as root.
        let script = """
        IFS= read -r PGPASSWORD || exit 90
        export PGPASSWORD
        psql -h \(Self.loopbackHost) -p \(port) -U \(Self.roleName) -d postgres -tAqc 'SELECT 1' 2>&1
        """
        let check = try await client.run(
            sudoPrefixed(script),
            stdin: Data((password + "\n").utf8),
            timeout: 60
        )
        let output = check.stdout + check.stderr

        guard check.succeeded, output.contains("1") else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "signing in as the new role",
                // PostgreSQL's own message is the most useful thing anyone can
                // be told here — "password authentication failed", "no
                // pg_hba.conf entry for host", "Connection refused" each point
                // at a different fix — so it is passed through with only the
                // secret itself removed.
                detail: Self.safeTail(output, hiding: password)
            )
        }
    }

    // MARK: - Agent configuration

    /// Point the agent at the role, the password and loopback TCP, preserving
    /// whatever else is in its config.
    ///
    /// Read, edit and rewrite in Swift rather than with `sed` on the server:
    /// the config is JSON, an operator may have hand-edited it, and a stream
    /// editor that half-matches would corrupt the file the agent needs to boot.
    private func pointAgentAtPostgres(port: Int) async throws -> Bool {
        let read = try await client.run(sudoPrefixed("cat \(Self.configPath)"), timeout: 30)
        guard read.succeeded, let data = read.stdout.data(using: .utf8) else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "reading the agent's configuration",
                detail: Self.safeTail(read.stderr)
            )
        }

        guard var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "reading the agent's configuration",
                detail: "\(Self.configPath) is not valid JSON."
            )
        }

        var postgres = root["postgres"] as? [String: Any] ?? [:]
        var changed = false

        // Every key the agent needs to reach PostgreSQL the way this
        // provisioning just set it up. Written explicitly rather than left to
        // the agent's defaults, so that a server provisioned today keeps
        // working if a default changes tomorrow.
        if postgres["password_file"] as? String != Self.passwordPath {
            postgres["password_file"] = Self.passwordPath
            changed = true
        }
        if postgres["host"] as? String != Self.loopbackHost {
            postgres["host"] = Self.loopbackHost
            changed = true
        }
        if postgres["port"] as? Int != port {
            postgres["port"] = port
            changed = true
        }
        if postgres["user"] as? String != Self.roleName {
            postgres["user"] = Self.roleName
            changed = true
        }
        if postgres["enabled"] as? Bool != true {
            postgres["enabled"] = true
            changed = true
        }
        guard changed else { return false }
        root["postgres"] = postgres

        let updated = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys]
        )

        let write = try await client.run(
            sudoPrefixed("""
            umask 077
            cat > \(Self.configPath).new || exit 91
            chmod 0600 \(Self.configPath).new || exit 92
            mv \(Self.configPath).new \(Self.configPath) || exit 93
            """),
            stdin: updated,
            timeout: 60
        )
        guard write.succeeded else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "updating the agent's configuration",
                detail: Self.safeTail(write.stderr.isEmpty ? write.stdout : write.stderr)
            )
        }
        return true
    }

    /// The agent reads its configuration once, at start.
    ///
    /// `systemctl restart` returns when the unit has been *started*, which is
    /// two claims short of what is needed here. A unit that exits on a
    /// configuration it dislikes is "started" and then "failed" a moment later.
    /// And even a healthy one is "active" before it has bound its socket — so
    /// the app, reconnecting the instant this returns, could get `connection
    /// refused` from an agent that was perfectly fine. Both are covered by
    /// waiting for the agent to answer its own health check.
    private func restartAgent(hiding secret: String) async throws -> Bool {
        let restart = try await client.run(
            sudoPrefixed("""
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart \(Self.serviceName) || exit 91
            else
                /etc/init.d/\(Self.serviceName) restart || exit 91
            fi
            \(AgentBootstrap.waitUntilServingScript(privileged: ""))
            """),  // no prefix inside: `sudoPrefixed` already runs the lot as root
            timeout: 150
        )
        guard restart.succeeded, restart.stdout.contains("serving=yes") else {
            throw ServerOSError.databaseProvisioningFailed(
                step: "restarting the agent",
                detail: Self.safeTail(restart.stdout + restart.stderr, hiding: secret)
            )
        }
        return true
    }

    // MARK: - Helpers

    /// `sudo -n` cannot be prefixed onto a multi-line script, so a script that
    /// needs root is fed to a privileged shell instead.
    ///
    /// Everything this type runs goes through here, so every script below can
    /// assume it is running as root — which is what lets `asPostgres` have one
    /// form instead of two.
    private func sudoPrefixed(_ script: String) -> String {
        privileged.isEmpty ? script : "\(privileged)/bin/sh -c \(Shell.quote(script))"
    }

    /// Write the password file and check it came out the way the agent needs
    /// it. Static so a test can read it — see the note at the call site.
    static func passwordFileScript() -> String {
        """
        umask 077
        cat > \(passwordPath) || exit 91
        chown root:root \(passwordPath) || exit 92
        chmod 0600 \(passwordPath) || exit 93
        owner=$(stat -c '%U' \(passwordPath) 2>/dev/null || stat -f '%Su' \(passwordPath) 2>/dev/null)
        mode=$(stat -c '%a' \(passwordPath) 2>/dev/null || stat -f '%Lp' \(passwordPath) 2>/dev/null)
        dirowner=$(stat -c '%U' \(configDirectory) 2>/dev/null || stat -f '%Su' \(configDirectory) 2>/dev/null)
        echo "owner=$owner mode=$mode dir=$dirowner"
        [ "$owner" = "root" ] || exit 94
        [ "$dirowner" = "root" ] || exit 95
        """
    }

    /// Run a command as the `postgres` operating-system user, from a script
    /// that is already running as root.
    ///
    /// This existed as `\(privileged)-u postgres psql …`, which is correct only
    /// when `privileged` is `"sudo -n "`. On a server reached as **root**,
    /// `privileged` is the empty string, and the command the shell received was
    ///
    ///     -u postgres psql -tAqc 'SELECT 1'
    ///
    /// whose first word is `-u`. There is no such command, so it failed, so the
    /// probe reported `admin=no`, so ServerOS told the user it "couldn't
    /// connect to PostgreSQL as an administrator. The cluster may be stopped" —
    /// about a cluster that was up and answering on port 5432. A message can be
    /// perfectly worded and still be a lie, if the thing it describes was never
    /// actually attempted.
    ///
    /// The mistake underneath was conflating two questions: *how does this
    /// account become root* (`privileged`) and *how does anything become
    /// postgres*. They are not the same question and they do not have the same
    /// answer.
    ///
    /// `su -s /bin/sh` rather than `sudo -u`: sudo is not installed on every
    /// server, and the postgres account's login shell is `/usr/sbin/nologin` on
    /// some images, which `su` would otherwise refuse.
    static func asPostgres(_ command: String) -> String {
        "su -s /bin/sh postgres -c \(Shell.quote(command))"
    }

    /// 32 bytes of system randomness, base64url, no padding. Generated on the
    /// Mac, written to the server, and deliberately never kept here: it is the
    /// server's secret, and ServerOS has no reason to hold a second copy.
    static func generatePassword() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255, using: &SystemRandomNumberGenerator.shared)
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Single quotes inside a PostgreSQL string literal are doubled. The
    /// generated password contains none, but a future change to the alphabet
    /// must not become an injection.
    static func escapeSQL(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "''")
    }

    /// The last line of command output, with one known secret removed from it.
    ///
    /// Used where the message itself is the valuable part — PostgreSQL
    /// distinguishes "password authentication failed" from "no pg_hba.conf
    /// entry for host" from "Connection refused", and each points at a
    /// different fix. Withholding all three because the word "password"
    /// appears would leave the user with nothing to act on, so the secret is
    /// struck out and the sentence survives.
    static func safeTail(_ text: String, hiding secret: String) -> String {
        let redacted = secret.isEmpty
            ? text
            : text.replacingOccurrences(of: secret, with: "«password»")
        let lines = redacted
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard let last = lines.last else { return "No output." }
        return String(last.prefix(300))
    }

    /// The last line of command output, and only if it cannot be carrying the
    /// password. psql echoes failing statements verbatim.
    static func safeTail(_ text: String) -> String {
        let lines = text
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        guard let last = lines.last else { return "No output." }
        if last.range(of: "PASSWORD", options: .caseInsensitive) != nil {
            return "PostgreSQL rejected the statement. The detail is withheld because it echoes the password."
        }
        return String(last.prefix(300))
    }

    static func labelled(_ output: String) -> [String: String] {
        var fields: [String: String] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            guard let separator = line.firstIndex(of: "=") else { continue }
            let key = String(line[line.startIndex..<separator]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            fields[key] = value
        }
        return fields
    }
}

extension SystemRandomNumberGenerator {
    /// One shared generator; `SystemRandomNumberGenerator` is stateless and
    /// draws from the system CSPRNG on every call.
    nonisolated(unsafe) static var shared = SystemRandomNumberGenerator()
}
