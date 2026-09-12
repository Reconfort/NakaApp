//  AgentBinaryTests.swift
//  ServerOSTests
//
//  The first time ServerOS was pointed at a real server, setup failed at the
//  last step: the installer tried to fetch the agent from a download host that
//  did not exist. Everything up to that point — SSH, the key, the capability
//  probe — had worked. The defect was that the app had no way to *supply* the
//  agent, only to name a URL and hope.
//
//  The fix is that the app carries the binary and pushes it over the SSH
//  connection it already holds. These tests cover the parts of that which are
//  pure logic: picking the right build for a server, forming the installer
//  arguments, and explaining a failure in terms of what was actually tried.

import XCTest
@testable import ServerOS

final class AgentBinaryTests: XCTestCase {

    // MARK: Architecture

    func testUnameVariantsMapToTheBuildsWeShip() {
        // Same hardware, different distributions. Getting this wrong uploads a
        // binary that cannot run, and the failure surfaces as a confusing
        // "does not run on this server" from the installer.
        for name in ["x86_64", "amd64", "x64", "X86_64", " x86_64\n"] {
            XCTAssertEqual(AgentBinary.normalise(name), "x86_64", "\(name)")
        }
        for name in ["aarch64", "arm64", "armv8l", "ARM64"] {
            XCTAssertEqual(AgentBinary.normalise(name), "aarch64", "\(name)")
        }
    }

    func testAnUnknownArchitectureIsPassedThroughRatherThanGuessed() {
        // A wrong guess installs a binary that cannot run. An unknown name is
        // reported as itself so the error can name it.
        XCTAssertEqual(AgentBinary.normalise("riscv64"), "riscv64")
        XCTAssertEqual(AgentBinary.normalise("ppc64le"), "ppc64le")
        XCTAssertEqual(AgentBinary.normalise(""), "")
    }

    func testResourceNamesFollowOneConvention() {
        XCTAssertEqual(AgentBinary.resourceName(for: "amd64"), "serveros-agent-linux-x86_64")
        XCTAssertEqual(AgentBinary.resourceName(for: "arm64"), "serveros-agent-linux-aarch64")
    }

    func testTheAppShipsAnAgentForAtLeastOneArchitecture() throws {
        // A build that carries no agent cannot set up any server, and would
        // only find that out in front of a user. `Bundle(for:)` is the test
        // bundle, which is where the resource lands under `xcodebuild test`.
        let bundle = Bundle(for: type(of: self))
        let architectures = AgentBinary.bundledArchitectures(in: bundle)
            + AgentBinary.bundledArchitectures(in: .main)
        try XCTSkipIf(architectures.isEmpty,
                      "No agent resource in either bundle under this test host.")
        XCTAssertTrue(architectures.contains("x86_64"),
                      "x86_64 is the common case and should always be bundled")
    }

    // MARK: Installer arguments

    func testABundledBinaryIsInstalledFromDiskRatherThanDownloaded() {
        let arguments = AgentBootstrap.installerArguments(
            options: InstallOptions(),
            requirements: Self.requirements(architecture: "x86_64"),
            binaryPath: "/tmp/serveros-agent-abc123"
        )

        XCTAssertTrue(arguments.contains("--binary '/tmp/serveros-agent-abc123'"), arguments)
        XCTAssertFalse(arguments.contains("--base-url"),
                       "an uploaded binary must not also ask the server to download one")
        XCTAssertTrue(arguments.contains("--no-start"), arguments)
    }

    func testAMirrorIsPassedThroughWhenOneIsConfigured() {
        var options = InstallOptions()
        options.binary = .download(baseURL: "https://mirror.example.com/serveros")

        let arguments = AgentBootstrap.installerArguments(
            options: options,
            requirements: Self.requirements(architecture: "x86_64"),
            binaryPath: nil
        )
        XCTAssertTrue(arguments.contains("--base-url 'https://mirror.example.com/serveros'"), arguments)
        XCTAssertFalse(arguments.contains("--binary"), arguments)
    }

    // MARK: Failure explanations

    func testAnUploadFailureDoesNotBlameTheNetwork() {
        // The whole point of uploading is that the server needs no internet.
        // Telling the user to check their server's connectivity after an upload
        // failed sends them to look where the problem cannot be.
        let causes = AgentBootstrap.installCauses(for: .bundled, path: "/tmp/serveros-agent-x")
        XCTAssertFalse(causes.contains { $0.lowercased().contains("reach") },
                       "\(causes)")
        XCTAssertTrue(causes.contains { $0.contains("space") }, "\(causes)")
    }

    func testADownloadFailureDoesNameTheHostItTried() {
        let causes = AgentBootstrap.installCauses(
            for: .download(baseURL: "https://mirror.example.com/serveros"),
            path: nil
        )
        XCTAssertTrue(causes.contains { $0.contains("mirror.example.com") }, "\(causes)")
    }

    func testAMissingBuildExplainsItselfAndIsNotRetryable() {
        let error = ServerOSError.agentBuildUnavailable(
            architecture: "riscv64",
            available: ["x86_64"]
        )
        XCTAssertFalse(error.isRetryable,
                       "pressing Try Again cannot conjure a build that isn't in the app")
        XCTAssertTrue(error.causes.contains { $0.contains("riscv64") }, "\(error.causes)")
        XCTAssertTrue(error.causes.contains { $0.contains("x86_64") },
                      "say what the app does have: \(error.causes)")
        XCTAssertTrue(error.causes.contains { $0.contains("cargo build") },
                      "say how to fix it: \(error.causes)")
    }

    // MARK: Helpers

    private static func requirements(architecture: String) -> AgentBootstrap.Requirements {
        AgentBootstrap.Requirements(
            uid: 0,
            hasSudo: true,
            hasSystemd: true,
            existingAgentVersion: nil,
            architecture: architecture
        )
    }
}
