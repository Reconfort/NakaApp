//  EnrollmentBundleTests.swift
//  ServerOSTests
//
//  The one line that turns a server into a paired server.
//
//  The agent prints
//
//      SERVEROS-ENROLLMENT-V1 <server_id> <secret_b64> <port> <version>
//
//  and this Mac has to find it in whatever else the SSH session produced. Two
//  parsers now exist for that line — `Enrollment::parse_bundle` in Rust and
//  `AgentBootstrap.parseEnrollmentBundle` here — so these cases are
//  deliberately the same cases as the agent's own tests, including the noisy
//  session and the malformed list.

import XCTest
@testable import ServerOS

final class EnrollmentBundleTests: XCTestCase {

    /// 32 bytes of 0x09, base64url, unpadded — 43 characters, which is the
    /// minimum length the agent's parser insists on.
    static let secret = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"

    func testParsesAWellFormedBundle() throws {
        let bundle = try XCTUnwrap(
            AgentBootstrap.parseEnrollmentBundle("SERVEROS-ENROLLMENT-V1 srv_abc123 \(Self.secret) 8723 0.1.0")
        )
        XCTAssertEqual(bundle.serverID, "srv_abc123")
        XCTAssertEqual(bundle.port, 8723)
        XCTAssertEqual(bundle.agentVersion, "0.1.0")
        XCTAssertEqual(bundle.secret, Data(repeating: 9, count: 32))
    }

    /// The reason the line is prefixed at all: a real session has a MOTD, an
    /// update notice and a sudo lecture in front of it.
    func testFindsTheBundleAmongSSHSessionNoise() throws {
        let session = """
        Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-40-generic x86_64)

         * Documentation:  https://help.ubuntu.com
         System information as of Fri 12 Sep 2026 09:15:03 AM UTC

          System load:  0.08              Processes:             132
          Usage of /:   48.2% of 49.2GB   Users logged in:       0

        12 updates can be applied immediately.

        [sudo] password for deploy:
        SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret) 8723 0.1.0
        Last login: Fri Sep 12 09:10:44 2026 from 10.0.0.4
        *** System restart required ***
        """

        let bundle = try XCTUnwrap(AgentBootstrap.parseEnrollmentBundle(session))
        XCTAssertEqual(bundle.serverID, "srv_x")
        XCTAssertEqual(bundle.port, 8723)
    }

    func testTheVersionFieldIsOptional() throws {
        let bundle = try XCTUnwrap(
            AgentBootstrap.parseEnrollmentBundle("SERVEROS-ENROLLMENT-V1 srv_old \(Self.secret) 8723")
        )
        XCTAssertNil(bundle.agentVersion)
        XCTAssertEqual(bundle.serverID, "srv_old")
    }

    func testToleratesCarriageReturnsAndIndentation() throws {
        let output = "noise\r\n    SERVEROS-ENROLLMENT-V1  srv_y  \(Self.secret)  9000  0.2.0   \r\nmore noise"
        let bundle = try XCTUnwrap(AgentBootstrap.parseEnrollmentBundle(output))
        XCTAssertEqual(bundle.serverID, "srv_y")
        XCTAssertEqual(bundle.port, 9000)
    }

    func testRejectsMalformedBundles() {
        let bad = [
            "",
            "SERVEROS-ENROLLMENT-V1",
            "SERVEROS-ENROLLMENT-V1 srv_x",
            "SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret)",                 // no port
            "SERVEROS-ENROLLMENT-V1 srv_x shortsecret 8723",               // secret too short
            "SERVEROS-ENROLLMENT-V1  \(Self.secret) 8723",                 // missing id
            "SERVEROS-ENROLLMENT-V2 srv_x \(Self.secret) 8723",            // wrong version
            "SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret) notaport",
            "SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret) 70000",           // beyond u16
            "SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret) -1",
            "prefixed SERVEROS-ENROLLMENT-V1 srv_x \(Self.secret) 8723",   // not the first field
            "Welcome to Ubuntu",
        ]
        for line in bad {
            XCTAssertNil(
                AgentBootstrap.parseEnrollmentBundle(line),
                "accepted a malformed bundle: \(line)"
            )
        }
    }

    func testRejectsASecretThatIsLongEnoughButNotBase64() {
        let notBase64 = String(repeating: "!", count: 50)
        XCTAssertNil(
            AgentBootstrap.parseEnrollmentBundle("SERVEROS-ENROLLMENT-V1 srv_x \(notBase64) 8723")
        )
    }

    func testTakesTheFirstBundleWhenTheOutputSomehowHasTwo() throws {
        let output = """
        SERVEROS-ENROLLMENT-V1 srv_first \(Self.secret) 8723 0.1.0
        SERVEROS-ENROLLMENT-V1 srv_second \(Self.secret) 8724 0.1.0
        """
        let bundle = try XCTUnwrap(AgentBootstrap.parseEnrollmentBundle(output))
        XCTAssertEqual(bundle.serverID, "srv_first")
    }

    // MARK: - base64url

    func testBase64URLDecodesTheAgentsAlphabet() throws {
        // The agent uses URL-safe, unpadded base64 — `-` and `_`, no `=`.
        let allBytes = Data((0...255).map { UInt8($0) })
        let encoded = Base64URL.encode(allBytes)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(Base64URL.decode(encoded), allBytes)
    }

    func testBase64URLReturnsNilRatherThanGuessing() {
        XCTAssertNil(Base64URL.decode("!!!!"))
        XCTAssertNil(Base64URL.decode("A"))   // 1 character can never be a byte
    }
}
