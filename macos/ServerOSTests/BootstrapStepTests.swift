//  BootstrapStepTests.swift
//  ServerOSTests
//
//  Microcopy is part of the product, so it gets tests like everything else.
//
//  A step title appears under a spinner while somebody waits for their server
//  to be set up. It has to be present tense, has to say what is happening, and
//  must not end in a full stop — a label is not a sentence. Those are cheap
//  rules to state and easy to break in a hurry, which is exactly what a test
//  is for.

import XCTest
@testable import ServerOS

final class BootstrapStepTests: XCTestCase {

    func testEveryStepHasATitle() {
        for step in BootstrapStep.allCases {
            XCTAssertFalse(step.title.isEmpty, "\(step) has no title")
            XCTAssertFalse(
                step.title.hasSuffix("."),
                "\(step): a progress label doesn't end in a full stop — “\(step.title)”"
            )
            XCTAssertFalse(step.title.hasSuffix("!"), "\(step) shouts")
            XCTAssertEqual(
                step.title.trimmingCharacters(in: .whitespaces),
                step.title,
                "\(step) has stray whitespace"
            )
        }
    }

    func testEveryTitleIsInTheProgressiveTense() {
        // "Installing the ServerOS agent…", not "Install the agent" and not
        // "Agent installation". Every title carries a present participle.
        for step in BootstrapStep.allCases {
            let words = step.title
                .split(whereSeparator: { $0.isWhitespace })
                .map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "…,.")) }
            XCTAssertTrue(
                words.contains(where: { $0.hasSuffix("ing") }),
                "\(step): “\(step.title)” doesn't read as something in progress"
            )
        }
    }

    func testTitlesAreDistinct() {
        let titles = BootstrapStep.allCases.map(\.title)
        XCTAssertEqual(
            Set(titles).count,
            titles.count,
            "two steps show the same label, so the user can't tell them apart"
        )
    }

    func testProgressOrderCoversEveryStepExactlyOnce() {
        XCTAssertEqual(
            Set(BootstrapStep.progressOrder),
            Set(BootstrapStep.allCases),
            "a step that never appears in progressOrder can never be shown"
        )
        XCTAssertEqual(BootstrapStep.progressOrder.count, BootstrapStep.allCases.count)
    }

    func testEnrollmentHappensBeforeTheAgentIsStarted() throws {
        // Not cosmetic: the agent reads its secret once at startup and exits if
        // there isn't one, so enrolling after starting would leave a dead
        // service and a setup flow that "succeeded".
        let enrolling = try XCTUnwrap(BootstrapStep.progressOrder.firstIndex(of: .enrolling))
        let starting = try XCTUnwrap(BootstrapStep.progressOrder.firstIndex(of: .startingAgent))
        XCTAssertLessThan(enrolling, starting)
    }

    func testDoneIsLast() {
        XCTAssertEqual(BootstrapStep.progressOrder.last, .done)
    }

    // MARK: - Reading the server

    func testProbeParsesUbuntu() throws {
        let output = """
        Linux
        x86_64
        6.8.0-40-generic
        PRETTY_NAME="Ubuntu 24.04.1 LTS"
        NAME="Ubuntu"
        VERSION_ID="24.04"
        VERSION="24.04.1 LTS (Noble Numbat)"
        ID=ubuntu
        ID_LIKE=debian
        HOME_URL="https://www.ubuntu.com/"
        """

        let probe = try XCTUnwrap(SystemProbe.parse(output))
        XCTAssertTrue(probe.isLinux)
        XCTAssertEqual(probe.machine, "x86_64")
        XCTAssertEqual(probe.kernel, "6.8.0-40-generic")
        XCTAssertEqual(probe.distributionID, "ubuntu")
        XCTAssertEqual(probe.prettyName, "Ubuntu 24.04.1 LTS")
        XCTAssertEqual(probe.versionID, "24.04")
        XCTAssertTrue(probe.isKnownDistribution)
    }

    func testProbeHandlesAServerWithNoOSRelease() throws {
        let probe = try XCTUnwrap(SystemProbe.parse("Linux\naarch64\n5.10.0\n"))
        XCTAssertTrue(probe.isLinux)
        XCTAssertEqual(probe.machine, "aarch64")
        XCTAssertNil(probe.distributionID)
        XCTAssertFalse(probe.isKnownDistribution, "an unknown distribution is a warning, not a claim")
    }

    func testProbeNoticesSomethingThatIsNotLinux() throws {
        let probe = try XCTUnwrap(SystemProbe.parse("Darwin\narm64\n23.5.0\n"))
        XCTAssertFalse(probe.isLinux)
        XCTAssertEqual(probe.systemName, "Darwin")
    }

    func testProbeNeedsAtLeastASystemAndAMachine() {
        XCTAssertNil(SystemProbe.parse(""))
        XCTAssertNil(SystemProbe.parse("Linux\n"))
    }

    func testLabelledFieldsReadsTheRequirementsScriptOutput() {
        let fields = AgentBootstrap.labelledFields("""
        uid=0
        sudo=yes
        systemd=yes
        agent=serveros-agent 0.1.0 (api v1)
        """)
        XCTAssertEqual(fields["uid"], "0")
        XCTAssertEqual(fields["sudo"], "yes")
        XCTAssertEqual(fields["agent"], "serveros-agent 0.1.0 (api v1)")
        XCTAssertNil(fields["nothing"])
    }

    func testInstallOutcomeIsReadOffTheOneLineTheInstallerPrints() {
        let outcome = AgentBootstrap.parseInstallOutcome("""
        SERVEROS-INSTALL-OK 0.1.0 x86_64 systemd
        """)
        XCTAssertEqual(outcome.version, "0.1.0")
        XCTAssertEqual(outcome.architecture, "x86_64")
        XCTAssertEqual(outcome.initSystem, "systemd")

        let empty = AgentBootstrap.parseInstallOutcome("something went sideways")
        XCTAssertNil(empty.version)
    }

    // MARK: - Shell quoting

    func testShellQuotingSurvivesTheNamesPeopleGiveTheirMacs() {
        XCTAssertEqual(Shell.quote("plain"), "'plain'")
        XCTAssertEqual(Shell.quote("Orion's MacBook"), "'Orion'\\''s MacBook'")
        XCTAssertEqual(Shell.quote("a b; rm -rf /"), "'a b; rm -rf /'")
        XCTAssertFalse(Shell.quote("$(whoami)").contains("\""))
    }
}
