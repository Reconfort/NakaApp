//  SSHKeyTests.swift
//  ServerOSTests
//
//  The wire format and the key we install on people's servers.
//
//  These are known-answer tests, not round-trip tests, wherever that is
//  possible: a round trip through two of my own functions proves they agree
//  with each other, not that either agrees with OpenSSH. The fixture below was
//  produced outside this codebase, so the assertions are against what a real
//  `sshd` would accept.

import XCTest
@testable import ServerOS

final class SSHKeyTests: XCTestCase {

    /// The public half of `SSHKeyFixtures.ed25519PrivateKey`, exactly as
    /// `ssh-keygen -y` writes it.
    static let knownPublicLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJVaSK1tNcGHq5Bg8zMMF7Pj3pGW1zmP71nw0Bx80/xl"
    static let knownSeedBase64 = "aVRY8wceAwwa02TlHLCWKqnd07L9qI4dmeJ9+KMo1Ps="
    static let knownFingerprint = "SHA256:qw3JB/sViOVcJw9pDz/jEzEEUNyKv6ZQ6JZymFx3rCs"

    // MARK: - The wire encoder

    func testWireStringIsFourByteLengthThenBytes() {
        XCTAssertEqual(Array(SSHWire.string(Data())), [0, 0, 0, 0])
        XCTAssertEqual(Array(SSHWire.string(Data([0xAA]))), [0, 0, 0, 1, 0xAA])

        let text = SSHWire.string("ssh-ed25519")
        XCTAssertEqual(Array(text.prefix(4)), [0, 0, 0, 11])
        XCTAssertEqual(String(data: text.dropFirst(4), encoding: .utf8), "ssh-ed25519")
    }

    func testWireStringHandlesALengthOverATwoByteBoundary() {
        let payload = Data(repeating: 0x7F, count: 300)
        let encoded = SSHWire.string(payload)
        XCTAssertEqual(Array(encoded.prefix(4)), [0, 0, 0x01, 0x2C])   // 300
        XCTAssertEqual(encoded.count, 304)
    }

    func testPublicKeyBlobMatchesTheFormatOpenSSHWrites() throws {
        let raw = Data(repeating: 0x11, count: 32)
        let blob = SSHWire.ed25519PublicKeyBlob(rawPublicKey: raw)

        var reader = SSHWireReader(blob)
        XCTAssertEqual(try reader.readText(), "ssh-ed25519")
        XCTAssertEqual(try reader.readString(), raw)
        XCTAssertEqual(reader.remainingCount, 0)
    }

    func testWireReaderRefusesToReadPastTheEnd() {
        var reader = SSHWireReader(Data([0, 0, 0, 8, 1, 2, 3]))
        XCTAssertThrowsError(try reader.readString()) { error in
            XCTAssertEqual(error as? SSHWireReader.ReadError, .truncated)
        }
    }

    func testBignumIsStrippedOfPaddingAndWidenedToTheCurveSize() throws {
        // A 33-byte mpint with the leading zero OpenSSH adds when the top bit
        // is set, and a short one that needs left-padding.
        let long = SSHWire.string(Data([0x00] + Array(repeating: 0xFF, count: 32)))
        var reader = SSHWireReader(long)
        let wide = try reader.readFixedWidthBignum(width: 32)
        XCTAssertEqual(wide, Data(repeating: 0xFF, count: 32))

        let short = SSHWire.string(Data([0x01, 0x02]))
        var shortReader = SSHWireReader(short)
        let padded = try shortReader.readFixedWidthBignum(width: 32)
        XCTAssertEqual(padded.count, 32)
        XCTAssertEqual(Array(padded.suffix(2)), [0x01, 0x02])
        XCTAssertEqual(Array(padded.prefix(30)), Array(repeating: 0, count: 30))
    }

    // MARK: - The keypair

    func testGeneratedKeyLooksLikeAnEd25519AuthorizedKeysLine() throws {
        // No space in the comment, so the three-field assertion below means
        // what it says; `testACommentWithSpacesIsStillOneLine` covers the rest.
        let pair = try ServerOSKeyPair.generate(comment: "serveros:Test-Mac")

        // Every Ed25519 public key blob starts with the same 15-byte header
        // (length 11, "ssh-ed25519", length 32), so every line starts with the
        // same base64 prefix. If this assertion fails the blob is wrong, and
        // sshd would reject the key.
        XCTAssertTrue(
            pair.publicKeyAuthorizedKeysLine.hasPrefix("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"),
            "unexpected line: \(pair.publicKeyAuthorizedKeysLine)"
        )
        XCTAssertTrue(pair.publicKeyAuthorizedKeysLine.hasSuffix(" serveros:Test-Mac"))
        XCTAssertEqual(pair.publicKeyAuthorizedKeysLine.split(separator: " ").count, 3)
        XCTAssertEqual(pair.privateKeySeed.count, 32)
    }

    func testACommentWithSpacesIsStillOneLine() throws {
        // `authorized_keys` treats everything after the key as the comment, so
        // a Mac called "Orion's MacBook Pro" is fine — as long as it stays on
        // one line.
        let pair = try ServerOSKeyPair.generate(comment: "serveros:Orion's MacBook Pro")
        XCTAssertTrue(pair.publicKeyAuthorizedKeysLine.hasSuffix(" serveros:Orion's MacBook Pro"))
        XCTAssertFalse(pair.publicKeyAuthorizedKeysLine.contains("\n"))
    }

    func testGeneratedKeysAreDifferentEveryTime() throws {
        let first = try ServerOSKeyPair.generate(comment: "serveros:Test")
        let second = try ServerOSKeyPair.generate(comment: "serveros:Test")
        XCTAssertNotEqual(first.privateKeySeed, second.privateKeySeed)
        XCTAssertNotEqual(first.publicKeyAuthorizedKeysLine, second.publicKeyAuthorizedKeysLine)
    }

    func testFingerprintIsTheFormatSSHKeygenPrints() throws {
        let pair = try ServerOSKeyPair.generate(comment: "serveros:Test")
        let fingerprint = pair.sha256Fingerprint

        XCTAssertTrue(fingerprint.hasPrefix("SHA256:"))
        let body = String(fingerprint.dropFirst("SHA256:".count))
        XCTAssertEqual(body.count, 43, "a SHA-256 digest is 43 unpadded base64 characters")
        XCTAssertFalse(body.contains("="), "the fingerprint must not be padded")
    }

    func testSeedRoundTripsToTheSameKey() throws {
        let original = try ServerOSKeyPair.generate(comment: "serveros:Round Trip")
        let restored = try ServerOSKeyPair.from(seed: original.privateKeySeed, comment: "serveros:Round Trip")

        XCTAssertEqual(restored.privateKeySeed, original.privateKeySeed)
        XCTAssertEqual(restored.publicKeyAuthorizedKeysLine, original.publicKeyAuthorizedKeysLine)
        XCTAssertEqual(restored.sha256Fingerprint, original.sha256Fingerprint)
    }

    /// The important one: a seed produced by `ssh-keygen` must give back the
    /// public key and fingerprint `ssh-keygen` printed for it.
    func testKnownSeedProducesTheKnownPublicKeyAndFingerprint() throws {
        let seed = try XCTUnwrap(Data(base64Encoded: Self.knownSeedBase64))
        let pair = try ServerOSKeyPair.from(seed: seed, comment: "serveros:Known")

        XCTAssertEqual(
            pair.publicKeyAuthorizedKeysLine,
            Self.knownPublicLine + " serveros:Known"
        )
        XCTAssertEqual(pair.sha256Fingerprint, Self.knownFingerprint)
    }

    func testWrongSizedSeedIsRejectedWithAReadableError() {
        XCTAssertThrowsError(try ServerOSKeyPair.from(seed: Data(repeating: 1, count: 16), comment: "x")) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_unusable")
            XCTAssertFalse(error.headline.isEmpty)
        }
    }

    func testCommentCannotSmuggleANewlineIntoAuthorizedKeys() throws {
        // authorized_keys is parsed line by line. A comment containing a
        // newline would append a second, attacker-chosen key.
        let pair = try ServerOSKeyPair.from(
            seed: Data(repeating: 7, count: 32),
            comment: "serveros:Mac\nssh-ed25519 AAAAsomethingelse attacker"
        )
        XCTAssertFalse(pair.publicKeyAuthorizedKeysLine.contains("\n"))
        XCTAssertEqual(pair.publicKeyAuthorizedKeysLine.split(whereSeparator: \.isNewline).count, 1)
    }

    func testEmptyCommentStillProducesAThreeFieldLine() throws {
        let pair = try ServerOSKeyPair.from(seed: Data(repeating: 3, count: 32), comment: "   ")
        XCTAssertEqual(pair.comment, "serveros")
        XCTAssertEqual(pair.publicKeyAuthorizedKeysLine.split(separator: " ").count, 3)
    }

    func testFingerprintOfAPublicKeyLineMatchesTheKeypairsOwn() throws {
        let pair = try ServerOSKeyPair.generate(comment: "serveros:Test")
        XCTAssertEqual(
            SSHFingerprint.sha256(ofOpenSSHPublicKey: pair.publicKeyAuthorizedKeysLine),
            pair.sha256Fingerprint
        )
        XCTAssertNil(SSHFingerprint.sha256(ofOpenSSHPublicKey: "not-a-key"))
    }

    // MARK: - Host key pinning

    func testPinnedKeyMatchesRegardlessOfTrailingComment() {
        let presented = Self.knownPublicLine
        let fingerprint = SSHFingerprint.sha256(ofOpenSSHPublicKey: presented) ?? ""

        XCTAssertTrue(HostKeyVerifier.matches(
            pinned: presented + " root@production",
            presented: presented,
            presentedFingerprint: fingerprint
        ))
        XCTAssertTrue(HostKeyVerifier.matches(
            pinned: Self.knownFingerprint,
            presented: presented,
            presentedFingerprint: fingerprint
        ))
    }

    func testADifferentKeyDoesNotMatch() throws {
        let other = try ServerOSKeyPair.generate(comment: "serveros:Other")
        let presented = Self.knownPublicLine
        let fingerprint = SSHFingerprint.sha256(ofOpenSSHPublicKey: presented) ?? ""

        XCTAssertFalse(HostKeyVerifier.matches(
            pinned: other.publicKeyAuthorizedKeysLine,
            presented: presented,
            presentedFingerprint: fingerprint
        ))
        XCTAssertFalse(HostKeyVerifier.matches(
            pinned: other.sha256Fingerprint,
            presented: presented,
            presentedFingerprint: fingerprint
        ))
        // Garbage in the pinned slot must never mean "accept".
        XCTAssertFalse(HostKeyVerifier.matches(
            pinned: "",
            presented: presented,
            presentedFingerprint: fingerprint
        ))
    }
}
