//  DatabaseProvisionerTests.swift
//  ServerOSTests
//
//  The first time ServerOS reached a real server's PostgreSQL, it reported —
//  correctly — that it had no account to sign in with, and then told the user
//  to open a terminal and run `psql`. That is the precise experience this
//  product exists to remove, and the user said so.
//
//  ServerOS is already holding an authenticated root SSH connection to that
//  machine. It can create the account itself. These tests cover the parts of
//  that which are decidable without a server: how the probe reads what it
//  finds, that the password is generated and handled safely, and that failures
//  name the step they stopped at.

import XCTest
@testable import ServerOS

final class DatabaseProvisionerTests: XCTestCase {

    // MARK: - Reading the server

    func testAProbeWithNoRoleIsNotConsideredProvisioned() {
        var probe = DatabaseProvisioner.Probe()
        probe.hasPsql = true
        probe.canAdminister = true
        XCTAssertFalse(probe.isAlreadyProvisioned)
        XCTAssertTrue(probe.canProvision, "psql and an admin connection are all it takes to try")
    }

    func testARoleThatExistsButCannotLogInStillNeedsWork() {
        // `CREATE ROLE x` without LOGIN is a group, not an account. A probe
        // that treated it as done would leave the agent unable to connect.
        var probe = DatabaseProvisioner.Probe()
        probe.hasPsql = true
        probe.canAdminister = true
        probe.roleExists = true
        probe.roleCanLogin = false
        probe.hasMonitor = true
        XCTAssertFalse(probe.isAlreadyProvisioned)
    }

    func testARoleWithoutMonitorStillNeedsWork() {
        var probe = DatabaseProvisioner.Probe()
        probe.roleExists = true
        probe.roleCanLogin = true
        probe.hasMonitor = false
        XCTAssertFalse(probe.isAlreadyProvisioned)
    }

    func testAFullyProvisionedServerIsRecognised() {
        var probe = DatabaseProvisioner.Probe()
        probe.hasPsql = true
        probe.canAdminister = true
        probe.roleExists = true
        probe.roleCanLogin = true
        probe.hasMonitor = true
        XCTAssertTrue(probe.isAlreadyProvisioned)
    }

    // MARK: - Becoming the postgres user
    //
    // The probe script was built as `\(privileged)-u postgres psql …`, which is
    // right only when `privileged` is "sudo -n ". Reached as root — the common
    // case, and the one this was tested on — `privileged` is empty and the
    // shell was handed `-u postgres psql -tAqc 'SELECT 1'`, whose first word is
    // `-u`. No such command, so it failed, so ServerOS reported that it
    // "couldn't connect to PostgreSQL as an administrator" about a cluster that
    // was up and serving. These tests read the generated script, because that
    // is the only place the mistake was visible.

    func testTheProbeRunsARealCommandRatherThanAnOption() {
        let script = DatabaseProvisioner.probeScript()
        for line in script.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            XCTAssertFalse(
                trimmed.hasPrefix("-") || trimmed.hasPrefix("if -") || trimmed.contains("$(-"),
                "a command that begins with an option is a command that does not exist: \(trimmed)"
            )
        }
    }

    func testEveryAdministratorQueryBecomesThePostgresUser() {
        let script = DatabaseProvisioner.probeScript()
        // Count invocations, not mentions: `command -v psql` asks whether the
        // binary exists and runs nothing, so it must not need a `su`. (The first
        // version of this counted "psql " and failed on exactly that line.)
        let psqlCalls = script.components(separatedBy: "psql -tAqc").count - 1
        let switches = script.components(separatedBy: "su -s /bin/sh postgres -c").count - 1
        XCTAssertGreaterThan(psqlCalls, 0)
        XCTAssertEqual(switches, psqlCalls, "every psql call has to run as postgres, not as whoever we are")
    }

    func testBecomingPostgresDoesNotDependOnSudoOrALoginShell() {
        let command = DatabaseProvisioner.asPostgres("psql -tAqc 'SELECT 1'")
        XCTAssertTrue(command.hasPrefix("su -s /bin/sh postgres -c"), command)
        XCTAssertFalse(command.contains("sudo"), "sudo isn't installed everywhere")
        XCTAssertTrue(command.contains(#"'\''SELECT 1'\''"#), "the inner quotes have to survive: \(command)")
    }

    func testAFailedAdministratorConnectionCarriesWhatTheServerSaid() {
        // The old script sent this to /dev/null and then guessed in the UI.
        let script = DatabaseProvisioner.probeScript()
        XCTAssertTrue(script.contains("adminerr="), script)

        let fields = DatabaseProvisioner.labelled("""
        admin=no
        adminerr=psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed
        """)
        XCTAssertTrue(fields["adminerr"]?.contains("connection to server") == true, "\(fields)")
    }

    // MARK: - The password file the agent has to read
    //
    // This was chowned to the `serveros` service account, which sounds right
    // and produced `/etc/serveros/postgres.pw: Permission denied (os error 13)`
    // from an agent running as **root**. The systemd unit sets
    // `CapabilityBoundingSet=` — empty — which strips CAP_DAC_OVERRIDE, and
    // that capability *is* root's power to ignore file permissions. Without it
    // uid 0 obeys ordinary DAC, and a 0600 file owned by someone else is shut.

    func testThePasswordFileIsOwnedByTheAccountTheAgentActuallyRunsAs() {
        let script = DatabaseProvisioner.passwordFileScript()
        XCTAssertTrue(script.contains("chown root:root"), script)
        XCTAssertFalse(
            script.contains("chown \(DatabaseProvisioner.serviceUser)"),
            "the agent runs as root with no capabilities; a file owned by serveros is unreadable to it"
        )
    }

    func testThePasswordFileStaysUnreadableToEveryoneElse() {
        XCTAssertTrue(DatabaseProvisioner.passwordFileScript().contains("chmod 0600"))
    }

    func testTheOwnershipIsCheckedRatherThanAssumed() {
        // The entire failure was ownership not being what the code assumed, so
        // assuming it again — even correctly — is not the fix.
        let script = DatabaseProvisioner.passwordFileScript()
        XCTAssertTrue(script.contains("stat"), script)
        XCTAssertTrue(script.contains(#"[ "$owner" = "root" ]"#), script)
        XCTAssertTrue(script.contains(#"[ "$dirowner" = "root" ]"#),
                      "a file you cannot traverse to is a file you cannot read")
    }

    func testWritingThePasswordNeverPutsItInTheCommand() {
        // It arrives on stdin. `ps` shows command lines to every user on the box.
        let script = DatabaseProvisioner.passwordFileScript()
        XCTAssertTrue(script.contains("cat > "), script)
        XCTAssertTrue(script.contains("umask 077"), "the file must never exist world-readable, even briefly")
    }

    // MARK: - Where PostgreSQL is listening
    //
    // The agent runs as root and connects over loopback TCP, because the Unix
    // socket lands on `local all all peer` — peer authentication matches the
    // OS user against the role name, so root is never serveros and no password
    // can help. That makes `listen_addresses` load-bearing.

    func testAStockDebianClusterIsReachableOnLoopback() {
        var probe = DatabaseProvisioner.Probe()
        probe.listenAddresses = "localhost"
        XCTAssertTrue(probe.listensOnLoopback)
    }

    func testListeningOnEverythingCountsAsLoopback() {
        var probe = DatabaseProvisioner.Probe()
        probe.listenAddresses = "*"
        XCTAssertTrue(probe.listensOnLoopback)
    }

    func testALoopbackEntryAmongOthersIsFound() {
        var probe = DatabaseProvisioner.Probe()
        probe.listenAddresses = "10.0.0.5, 127.0.0.1"
        XCTAssertTrue(probe.listensOnLoopback, "whitespace after the comma is how psql prints it")
    }

    func testAClusterBoundToOnePrivateInterfaceIsNotReachable() {
        // A real configuration, and one to stop on with an explanation rather
        // than fail three steps later with "Connection refused".
        var probe = DatabaseProvisioner.Probe()
        probe.listenAddresses = "10.0.0.5"
        XCTAssertFalse(probe.listensOnLoopback)
    }

    func testAClusterWithNoListenerAtAllIsNotReachable() {
        var probe = DatabaseProvisioner.Probe()
        probe.listenAddresses = ""
        XCTAssertFalse(probe.listensOnLoopback)
    }

    func testTheListenerAndPortAreReadFromTheProbe() {
        let fields = DatabaseProvisioner.labelled("""
        psql=yes
        admin=yes
        listen=localhost
        pgport=5433
        """)
        XCTAssertEqual(fields["listen"], "localhost")
        XCTAssertEqual(fields["pgport"], "5433", "not every cluster is on 5432")
    }

    func testProbeOutputIsParsedFieldByField() {
        let fields = DatabaseProvisioner.labelled("""
        psql=yes
        svcuser=yes
        admin=yes
        role=t
        monitor=f
        """)
        XCTAssertEqual(fields["psql"], "yes")
        XCTAssertEqual(fields["role"], "t")
        XCTAssertEqual(fields["monitor"], "f")
    }

    // MARK: - The password

    func testGeneratedPasswordsAreLongAndUnique() {
        let first = DatabaseProvisioner.generatePassword()
        let second = DatabaseProvisioner.generatePassword()
        XCTAssertNotEqual(first, second)
        XCTAssertGreaterThanOrEqual(first.count, 40, "32 bytes of entropy, base64")
    }

    func testGeneratedPasswordsSurviveShellAndSQLWithoutEscaping() {
        // The alphabet is deliberately base64url: no quotes, no backslashes, no
        // shell metacharacters. A password that needed escaping to be safe
        // would be one bad edit away from an injection.
        let forbidden = CharacterSet(charactersIn: "'\"\\`$();|&<> \n\t")
        for _ in 0..<200 {
            let password = DatabaseProvisioner.generatePassword()
            XCTAssertNil(
                password.rangeOfCharacter(from: forbidden),
                "generated password contained a character needing escaping: \(password)"
            )
        }
    }

    func testSQLEscapingDoublesQuotes() {
        // Belt and braces: the generator never emits one, but the escape has to
        // be correct if the alphabet ever changes.
        XCTAssertEqual(DatabaseProvisioner.escapeSQL("it's"), "it''s")
        XCTAssertEqual(DatabaseProvisioner.escapeSQL("plain"), "plain")
    }

    func testOutputThatCouldEchoThePasswordIsWithheld() {
        // psql prints the statement it failed on. That statement contains
        // ALTER ROLE … PASSWORD '…', so the raw tail can never be shown.
        let echoed = "ERROR:  syntax error\nSTATEMENT:  ALTER ROLE serveros LOGIN PASSWORD 'hunter2'"
        let safe = DatabaseProvisioner.safeTail(echoed)
        XCTAssertFalse(safe.contains("hunter2"), safe)
        XCTAssertTrue(safe.contains("withheld"), safe)
    }

    func testOrdinaryOutputIsPassedThrough() {
        let safe = DatabaseProvisioner.safeTail("could not connect to server: No such file or directory")
        XCTAssertTrue(safe.contains("No such file"), safe)
    }

    func testTheSignInErrorSurvivesRedaction() {
        // This is the sentence that tells anyone what is actually wrong, and
        // the blanket "contains PASSWORD → withhold" rule would have thrown it
        // away. The secret is struck out; the diagnosis stays.
        let message = #"psql: error: connection to server at "127.0.0.1", port 5432 failed: """#
            + "FATAL:  password authentication failed for user \"serveros\""
        let safe = DatabaseProvisioner.safeTail(message, hiding: "s3cr3t-value")
        XCTAssertTrue(safe.contains("password authentication failed"), safe)
    }

    func testTheSecretItselfIsNeverPassedThrough() {
        let secret = "Zm9vYmFyLXNlY3JldA"
        let safe = DatabaseProvisioner.safeTail("psql: FATAL: bad password \(secret) rejected", hiding: secret)
        XCTAssertFalse(safe.contains(secret), safe)
        XCTAssertTrue(safe.contains("«password»"), safe)
    }

    func testRedactionOfEmptyOutputStillSaysSomething() {
        XCTAssertEqual(DatabaseProvisioner.safeTail("\n  \n", hiding: "x"), "No output.")
    }

    // MARK: - What the user is told

    func testTheSummarySaysWhatActuallyChanged() {
        var outcome = DatabaseProvisioner.Outcome()
        outcome.createdRole = true
        outcome.grantedMonitor = true
        outcome.setPassword = true
        outcome.verified = true
        outcome.restartedAgent = true
        XCTAssertTrue(outcome.summary.contains("Created the serveros role"), outcome.summary)
        XCTAssertTrue(outcome.summary.contains("pg_monitor"), outcome.summary)
    }

    func testSuccessIsOnlyClaimedWhenTheSignInWasActuallyChecked() {
        // The first version of this said "database access is set up" and the
        // screen underneath still said the credentials were rejected. Nothing
        // in the summary may imply a verification that did not happen.
        var unchecked = DatabaseProvisioner.Outcome()
        unchecked.createdRole = true
        unchecked.setPassword = true
        XCTAssertFalse(unchecked.summary.contains("check"), unchecked.summary)

        var checked = unchecked
        checked.verified = true
        XCTAssertTrue(checked.summary.contains("signed in with it to check that it works"), checked.summary)
    }

    func testAnAlreadyProvisionedServerDoesNotClaimToHaveCreatedAnything() {
        var outcome = DatabaseProvisioner.Outcome()
        outcome.createdRole = false
        outcome.grantedMonitor = true
        XCTAssertTrue(outcome.summary.contains("already there"), outcome.summary)
    }

    func testAFailureNamesTheStepAndSaysRetryingIsSafe() {
        let error = ServerOSError.databaseProvisioningFailed(
            step: "restarting the agent",
            detail: "Job for serveros-agent.service failed"
        )
        XCTAssertTrue(error.isRetryable, "provisioning is idempotent, so Try Again is the right advice")
        XCTAssertTrue(error.causes.contains { $0.contains("restarting the agent") }, "\(error.causes)")
        XCTAssertTrue(error.causes.contains { $0.contains("half-applied") }, "\(error.causes)")
    }

    func testAnImpossibleServerIsNotOfferedARetry() {
        let error = ServerOSError.databaseProvisioningUnavailable(
            reason: "psql isn't installed on this server, so ServerOS has no way to talk to PostgreSQL."
        )
        XCTAssertFalse(error.isRetryable, "pressing Try Again cannot install psql")
        XCTAssertTrue(error.causes.contains { $0.contains("psql") }, "\(error.causes)")
    }
}
