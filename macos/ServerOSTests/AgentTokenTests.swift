//  AgentTokenTests.swift
//  ServerOSTests
//
//  The token format, verified against the agent's own rules.
//
//  These assertions are transcribed from `agent/crates/agent/src/auth.rs`:
//  three dot-separated parts, the literal prefix `serveros`, unpadded
//  base64url, a compact JSON payload with five claims, an HMAC-SHA256 over
//  `"serveros." + payload`, a lifetime the agent caps at 300 seconds, and a
//  `jti` that must never repeat.
//
//  The signature check here recomputes the MAC independently rather than
//  calling the minter twice — a test that used the same code path to produce
//  and to verify would pass no matter what that code path did.

import CryptoKit
import XCTest
@testable import ServerOS

final class AgentTokenTests: XCTestCase {

    /// A fixed 32-byte key, so the expected MAC is reproducible.
    private let secret = Data(repeating: 0x2A, count: 32)

    private func makeMinter(subject: String = "Test Mac") -> AgentTokenMinter {
        AgentTokenMinter(secret: secret, subject: subject)
    }

    /// Split a token and return its three parts.
    private func parts(of token: String) throws -> (prefix: String, payload: String, signature: String) {
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(pieces.count, 3, "A token has exactly three dot-separated parts")
        guard pieces.count == 3 else { throw TokenTestError.malformed }
        return (pieces[0], pieces[1], pieces[2])
    }

    private func claims(of token: String) throws -> [String: Any] {
        let split = try parts(of: token)
        let payloadData = try XCTUnwrap(
            AgentTokenMinter.base64URLDecode(split.payload),
            "payload is not base64url"
        )
        let object = try JSONSerialization.jsonObject(with: payloadData)
        return try XCTUnwrap(object as? [String: Any], "payload is not a JSON object")
    }

    enum TokenTestError: Error { case malformed }

    // MARK: - Shape

    func testTokenHasThreePartsAndTheAgentsPrefix() throws {
        let token = makeMinter().mint(scopes: [.read])
        let split = try parts(of: token)

        XCTAssertEqual(split.prefix, "serveros")
        XCTAssertEqual(split.prefix, AgentTokenMinter.prefix)
        XCTAssertFalse(split.payload.isEmpty)
        XCTAssertFalse(split.signature.isEmpty)
    }

    func testEveryPartIsUnpaddedBase64URL() throws {
        // Padding, `+` and `/` would all survive a header but not a query
        // string, and the agent's decoder is written for the URL alphabet.
        for _ in 0..<32 {
            let token = makeMinter().mint(scopes: [.read, .write, .admin])
            let split = try parts(of: token)
            for part in [split.payload, split.signature] {
                XCTAssertFalse(part.contains("="), "base64url is unpadded")
                XCTAssertFalse(part.contains("+"), "base64url uses - not +")
                XCTAssertFalse(part.contains("/"), "base64url uses _ not /")
            }
        }
    }

    // MARK: - Claims

    func testClaimsMatchTheAgentsExpectations() throws {
        let before = Int64(Date().timeIntervalSince1970)
        let token = makeMinter(subject: "Abebe Mac").mint(scopes: [.read, .write], lifetime: 120)
        let after = Int64(Date().timeIntervalSince1970)

        let payload = try claims(of: token)

        XCTAssertEqual(payload["sub"] as? String, "Abebe Mac")
        XCTAssertEqual(payload["scp"] as? String, "read write")

        let issued = try XCTUnwrap((payload["iat"] as? NSNumber)?.int64Value)
        let expires = try XCTUnwrap((payload["exp"] as? NSNumber)?.int64Value)
        XCTAssertGreaterThanOrEqual(issued, before)
        XCTAssertLessThanOrEqual(issued, after)
        XCTAssertEqual(expires - issued, 120)

        let identifier = try XCTUnwrap(payload["jti"] as? String)
        XCTAssertFalse(identifier.isEmpty)
        // 16 random bytes, unpadded base64url.
        XCTAssertEqual(identifier.count, 22)
        XCTAssertEqual(AgentTokenMinter.base64URLDecode(identifier)?.count, 16)

        XCTAssertEqual(payload.count, 5, "The agent reads exactly sub, iat, exp, jti and scp")
    }

    func testScopesAreOrderedLeastToMostPrivileged() throws {
        let token = makeMinter().mint(scopes: [.admin, .read, .write])
        XCTAssertEqual(try claims(of: token)["scp"] as? String, "read write admin")
    }

    func testDuplicateScopesAreCollapsed() throws {
        let token = makeMinter().mint(scopes: [.read, .read, .write])
        XCTAssertEqual(try claims(of: token)["scp"] as? String, "read write")
    }

    func testEmptyScopesFallBackToRead() throws {
        // The agent rejects a token with no recognised scope outright, so an
        // empty request must not produce one.
        let token = makeMinter().mint(scopes: [])
        XCTAssertEqual(try claims(of: token)["scp"] as? String, "read")
    }

    // MARK: - Signature

    func testSignatureIsAnIndependentlyReproducibleHMAC() throws {
        let token = makeMinter(subject: "Signing Mac").mint(scopes: [.read])
        let split = try parts(of: token)

        // Recompute from first principles: HMAC-SHA256 over the literal string
        // "serveros.<payload>", keyed with the shared secret.
        let signingInput = "serveros.\(split.payload)"
        let expected = HMAC<SHA256>.authenticationCode(
            for: Data(signingInput.utf8),
            using: SymmetricKey(data: secret)
        )
        let expectedData = Data(expected)
        XCTAssertEqual(expectedData.count, 32)

        let actual = try XCTUnwrap(AgentTokenMinter.base64URLDecode(split.signature))
        XCTAssertEqual(actual, expectedData)
    }

    func testADifferentSecretProducesADifferentSignature() throws {
        let subject = "Same Mac"
        let one = AgentTokenMinter(secret: Data(repeating: 0x01, count: 32), subject: subject)
        let two = AgentTokenMinter(secret: Data(repeating: 0x02, count: 32), subject: subject)

        // Sign identical payloads so only the key differs.
        let payload = AgentTokenMinter.payloadJSON(
            subject: subject, issuedAt: 1_789_210_483, expiresAt: 1_789_210_603,
            tokenID: "AAAAAAAAAAAAAAAAAAAAAA", scopes: [.read]
        )
        let encoded = AgentTokenMinter.base64URLEncode(Data(payload.utf8))
        let input = Data("serveros.\(encoded)".utf8)

        let macOne = Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: Data(repeating: 0x01, count: 32))))
        let macTwo = Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: Data(repeating: 0x02, count: 32))))
        XCTAssertNotEqual(macOne, macTwo)

        // And the minters, which is what actually matters.
        XCTAssertNotEqual(one.mint(scopes: [.read]), two.mint(scopes: [.read]))
    }

    // MARK: - Replay

    func testEveryMintIsUniqueBecauseOfTheTokenID() throws {
        // The agent remembers recent `jti` values and refuses a repeat, so a
        // cached token would work exactly once. Two mints must never match.
        var identifiers = Set<String>()
        var tokens = Set<String>()
        let minter = makeMinter()

        for _ in 0..<200 {
            let token = minter.mint(scopes: [.read])
            tokens.insert(token)
            identifiers.insert(try XCTUnwrap(claims(of: token)["jti"] as? String))
        }

        XCTAssertEqual(identifiers.count, 200, "jti must be unique per token")
        XCTAssertEqual(tokens.count, 200, "no two tokens may be identical")
    }

    // MARK: - Lifetime

    func testLifetimeIsCappedAtTheAgentsMaximum() throws {
        // `MAX_TOKEN_LIFETIME_SECS` is 300 and the agent rejects anything
        // longer outright rather than trimming it, so asking for an hour must
        // produce a five-minute token rather than a refused one.
        let token = makeMinter().mint(scopes: [.read], lifetime: 3_600)
        let payload = try claims(of: token)
        let issued = try XCTUnwrap((payload["iat"] as? NSNumber)?.int64Value)
        let expires = try XCTUnwrap((payload["exp"] as? NSNumber)?.int64Value)

        XCTAssertEqual(expires - issued, 300)
        XCTAssertEqual(AgentTokenMinter.maximumLifetime, 300)
    }

    func testLifetimeHasAFloor() throws {
        // Below the floor, ordinary clock drift between Mac and server matters
        // more than the token does.
        let token = makeMinter().mint(scopes: [.read], lifetime: 1)
        let payload = try claims(of: token)
        let issued = try XCTUnwrap((payload["iat"] as? NSNumber)?.int64Value)
        let expires = try XCTUnwrap((payload["exp"] as? NSNumber)?.int64Value)

        XCTAssertEqual(expires - issued, Int64(AgentTokenMinter.minimumLifetime))
    }

    func testNegativeLifetimeStillProducesAUsableToken() throws {
        let token = makeMinter().mint(scopes: [.read], lifetime: -500)
        let payload = try claims(of: token)
        let issued = try XCTUnwrap((payload["iat"] as? NSNumber)?.int64Value)
        let expires = try XCTUnwrap((payload["exp"] as? NSNumber)?.int64Value)
        XCTAssertGreaterThan(expires, issued)
    }

    // MARK: - Subject

    func testSubjectIsReducedToCharactersThatNeedNoEscaping() {
        // The payload is assembled as text so minting cannot throw. That is
        // only safe while the one free-form field cannot carry a quote, a
        // backslash or a control character.
        let awkward = "Bob\"s \\Mac\n\u{0007}"
        let cleaned = AgentTokenMinter.sanitisedSubject(awkward)

        XCTAssertFalse(cleaned.contains("\""))
        XCTAssertFalse(cleaned.contains("\\"))
        XCTAssertFalse(cleaned.contains("\n"))
        XCTAssertFalse(cleaned.contains("\u{0007}"))
        XCTAssertTrue(cleaned.hasPrefix("Bob"))
    }

    func testAnAwkwardSubjectStillYieldsParseableJSON() throws {
        let token = AgentTokenMinter(secret: secret, subject: "\"; DROP TABLE servers; --")
            .mint(scopes: [.read])
        let payload = try claims(of: token)
        XCTAssertNotNil(payload["sub"] as? String)
    }

    func testAnEmptySubjectFallsBackRatherThanProducingAnEmptyClaim() {
        XCTAssertEqual(AgentTokenMinter.sanitisedSubject("   "), "ServerOS for Mac")
        XCTAssertEqual(AgentTokenMinter.sanitisedSubject(""), "ServerOS for Mac")
    }

    func testSubjectIsBounded() {
        let long = String(repeating: "a", count: 500)
        XCTAssertEqual(AgentTokenMinter.sanitisedSubject(long).count, 64)
    }

    func testDefaultSubjectIsNeverEmpty() {
        XCTAssertFalse(AgentTokenMinter.defaultSubject().isEmpty)
    }

    // MARK: - Base64url helpers

    func testBase64URLRoundTrips() throws {
        for length in 0...64 {
            var bytes: [UInt8] = []
            for index in 0..<length {
                bytes.append(UInt8(index % 251))
            }
            let data = Data(bytes)
            let encoded = AgentTokenMinter.base64URLEncode(data)
            XCTAssertEqual(AgentTokenMinter.base64URLDecode(encoded), data, "length \(length)")
        }
    }

    func testBase64URLMatchesTheKnownVector() {
        // RFC 4648 §10, minus the padding.
        XCTAssertEqual(AgentTokenMinter.base64URLEncode(Data("f".utf8)), "Zg")
        XCTAssertEqual(AgentTokenMinter.base64URLEncode(Data("fo".utf8)), "Zm8")
        XCTAssertEqual(AgentTokenMinter.base64URLEncode(Data("foo".utf8)), "Zm9v")
        XCTAssertEqual(AgentTokenMinter.base64URLEncode(Data("foob".utf8)), "Zm9vYg")
    }

    func testBase64URLRejectsAnImpossibleLength() {
        // A single trailing character cannot be a whole byte.
        XCTAssertNil(AgentTokenMinter.base64URLDecode("Zm9vY"))
    }

    // MARK: - Payload text

    func testPayloadJSONIsCompactAndInTheAgentsFieldOrder() {
        let payload = AgentTokenMinter.payloadJSON(
            subject: "Mac",
            issuedAt: 1_789_210_483,
            expiresAt: 1_789_210_603,
            tokenID: "3Qk",
            scopes: [.read, .write]
        )
        XCTAssertEqual(
            payload,
            "{\"sub\":\"Mac\",\"iat\":1789210483,\"exp\":1789210603,\"jti\":\"3Qk\",\"scp\":\"read write\"}"
        )
        XCTAssertFalse(payload.contains(" \""), "the payload is compact — no spaces after separators")
    }
}
