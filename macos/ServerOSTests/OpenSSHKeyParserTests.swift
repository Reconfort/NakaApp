//  OpenSSHKeyParserTests.swift
//  ServerOSTests
//
//  Real key files, not synthesised ones.
//
//  Every fixture below was written by a real OpenSSH serialiser, not by the
//  parser under test. The Ed25519 case asserts that the seed we extract
//  reproduces the public key that shipped with the file — which is the only
//  assertion that proves the parse was right rather than merely self-consistent.

import XCTest
@testable import ServerOS

enum SSHKeyFixtures {

    /// `ssh-keygen -t ed25519 -N "" -f /tmp/k`, unencrypted, empty comment.
    static let ed25519PrivateKey = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx
    OQAAACCVWkitbTXBh6uQYPMzDBez496Rltc5j+9Z8NAcfNP8ZQAAAIjUMJxG1DCcRgAAAAtzc2gt
    ZWQyNTUxOQAAACCVWkitbTXBh6uQYPMzDBez496Rltc5j+9Z8NAcfNP8ZQAAAEBpVFjzBx4DDBrT
    ZOUcsJYqqd3Tsv2ojh2Z4n34oyjU+5VaSK1tNcGHq5Bg8zMMF7Pj3pGW1zmP71nw0Bx80/xlAAAA
    AAECAwQF
    -----END OPENSSH PRIVATE KEY-----
    """

    static let ed25519PublicKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJVaSK1tNcGHq5Bg8zMMF7Pj3pGW1zmP71nw0Bx80/xl"

    static let ed25519SeedBase64 = "aVRY8wceAwwa02TlHLCWKqnd07L9qI4dmeJ9+KMo1Ps="

    /// The same container shape with `ciphername` = `aes256-ctr` and
    /// `kdfname` = `bcrypt`, i.e. what `ssh-keygen` writes when you give it a
    /// passphrase. The body is unreadable by design — the parser must refuse
    /// before it ever gets there.
    static let ed25519EncryptedPrivateKey = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwbVTekS
    40BIQw+n92IXGSAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJVaSK1tNcGHq5Bg
    8zMMF7Pj3pGW1zmP71nw0Bx80/xlAAAAgItHveDFCfdbJAjYTA4RuIeJW+zlXNg1prW6JN
    n9yIgkDkRgH5pRPR81El04dAOvy+X0xeXDQ8/+kiBi3v+ZMOhZP9XfnPvgeqQ3NCMRMFV9
    Dhv65BrhuwNjuK7ohS3XTG65j5ecUDeSQ+OUITv/fDZsQGVxEDuGd2FLfWG9WwIT
    -----END OPENSSH PRIVATE KEY-----
    """

    /// `ssh-keygen -t rsa -b 2048`. Unencrypted, and still unusable.
    static let rsaPrivateKey = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcnNhAAAA
    AwEAAQAAAQEAo0OuQUNg/KyaZERYWbtbjn2eLco0Ya9nwukHSqNU+CgU7CVSOVyI6XxAnRgvwefu
    7j2LUnvZae6GtePZy6z6rZZegC93JHsR+PsdO+4c+rcDUBceMtBDX4Y//1jIMUL0ZDe7AsxZPILX
    j70dZf0tG7Lo1/BaZlPz0qtv+T6/CRHt/sNGccKxmYKwNZA80RvubNu2/O7RjVXWqzaWpOsnKMTo
    /he8sLy3RgUw+bV/2R+5AtlGms1mEuI66BkzHxMJtQbpK4aKHfZ3BHG+JFnRkN3emke0pi10dMh/
    Z9yABK0CksilLir2lCs6cAnUZ2F0tZf6BQsVMoKM5tgOZ8LxUQAAA7iDlxIBg5cSAQAAAAdzc2gt
    cnNhAAABAQCjQ65BQ2D8rJpkRFhZu1uOfZ4tyjRhr2fC6QdKo1T4KBTsJVI5XIjpfECdGC/B5+7u
    PYtSe9lp7oa149nLrPqtll6AL3ckexH4+x077hz6twNQFx4y0ENfhj//WMgxQvRkN7sCzFk8gteP
    vR1l/S0bsujX8FpmU/PSq2/5Pr8JEe3+w0ZxwrGZgrA1kDzRG+5s27b87tGNVdarNpak6ycoxOj+
    F7ywvLdGBTD5tX/ZH7kC2UaazWYS4jroGTMfEwm1Bukrhood9ncEcb4kWdGQ3d6aR7SmLXR0yH9n
    3IAErQKSyKUuKvaUKzpwCdRnYXS1l/oFCxUygozm2A5nwvFRAAAAAwEAAQAAAQAzFdngFO+zkGSM
    7C/DABOBbgABLuyeBk8O13CPI7VSIuSNEY59YV17xYPIRAmpgGOsSzideiBI+7hOELoU947Goy71
    qCR9Fz9D63s1xeducbaJKHqsBquWJ8E9qm+VrnAfLasIEJ35h61gjhm1UHd9W8lszAnVS/6WlEso
    r8AB24iR6WIcoqi8CysFRpqU/IvfaPnqA8ijhh95d2XIn6amO41l2UVEL5hrYTscl18RpDkZuAzU
    cL6LSRKdP3WrZ3un4xHUCoDwduLyfImX+jSy9Stu6/AP24xOAGRiNHligDFOOSpLoyOB6WbAnxbW
    wnu1c01jYki68+fs9MUmTgRjAAAAgQCVSqNvWglDkT84AcmkRTr+zfAUfpdrIXFP8xVOXtX3wFA+
    EwkRfjjUkPRb05Qil1JK+mcqy72chRuL4eDCkzC0SCP/FSvqugqLd4UWlai0ouksscVjPbVQkIWT
    5l4sUQmtkDixlVjUpO5h/5TJjLKVQj1U30fre6betN7Az8yhewAAAIEA3Ga04QMsu3IihLyddGCX
    I3fz9fPu89R+2RatLcAFZ1uymIMA0y6YlrMCkp/k3tNKlIcvF7TQNTK41onu1H//xEsUD0BJIZfi
    /2ZRGuqUMCmzQaUbTJLUtUCR+oPbZNwLkEh4ynha9aq03rAxePav6WXCnG3fFxBxR5N3PyqkwRsA
    AACBAL2icYFTr5rgKau4PwRxJ18nJ5emvJUeTiSEJz8CtBXHXSje7U1S0QvB/C1P0/3L3DYqyuPo
    dbwx6rykssTnOuGzZQA3zJX1hxsx8uu2g1n+TCvKXjLVozxo+s9vzNqUgKqRifQ0ZkhE3Sxd3h51
    YI/Wi+gKUIATEQEA2euVFuoDAAAAAAEC
    -----END OPENSSH PRIVATE KEY-----
    """

    /// `ssh-keygen -t ecdsa -b 256`.
    static let p256PrivateKey = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
    LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQLGFM3iiTs5ucoF5Cr7cpswXGhCCZPtYJGNnhlbjtt
    cetrKXGQuCzOz9i2D4o3kfgPaP+KiMvvEFC7KjyupIVhAAAAoA+OsIAPjrCAAAAAE2VjZHNhLXNo
    YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAsYUzeKJOzm5ygXkKvtymzBcaEIJk+1gkY2eGVu
    O21x62spcZC4LM7P2LYPijeR+A9o/4qIy+8QULsqPK6khWEAAAAgWDpVT7e5ANDU6lt4qM6sveR4
    XCKYMcEEpnMROOZe/xMAAAAAAQIDBAUGBwg=
    -----END OPENSSH PRIVATE KEY-----
    """

    static let p256PublicKey =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAsYUzeKJOzm5ygXkKvtymzBcaEIJk+1gkY2eGVuO21x62spcZC4LM7P2LYPijeR+A9o/4qIy+8QULsqPK6khWE="

    static let p256ScalarBase64 = "WDpVT7e5ANDU6lt4qM6sveR4XCKYMcEEpnMROOZe/xM="

    /// The same P-256 key as SEC1 PEM, i.e. `ssh-keygen -m PEM`.
    static let p256SEC1PrivateKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIFg6VU+3uQDQ1OpbeKjOrL3keFwimDHBBKZzETjmXv8ToAoGCCqGSM49
    AwEHoUQDQgAECxhTN4ok7ObnKBeQq+3KbMFxoQgmT7WCRjZ4ZW47bXHraylxkLgs
    zs/Ytg+KN5H4D2j/iojL7xBQuyo8rqSFYQ==
    -----END EC PRIVATE KEY-----
    """
}

final class OpenSSHKeyParserTests: XCTestCase {

    // MARK: - Keys that work

    func testParsesARealUnencryptedEd25519Key() throws {
        let parsed = try OpenSSHKeyParser.parse(SSHKeyFixtures.ed25519PrivateKey)

        guard case .ed25519(let seed) = parsed else {
            return XCTFail("expected an Ed25519 key, got \(parsed)")
        }
        XCTAssertEqual(seed.count, 32)
        XCTAssertEqual(seed, Data(base64Encoded: SSHKeyFixtures.ed25519SeedBase64))
    }

    /// The assertion that matters: the seed we pulled out has to regenerate the
    /// public key that was in the file. Anything less proves nothing.
    func testTheParsedSeedReproducesTheKeysOwnPublicKey() throws {
        let parsed = try OpenSSHKeyParser.parse(SSHKeyFixtures.ed25519PrivateKey)
        guard case .ed25519(let seed) = parsed else { return XCTFail("expected an Ed25519 key") }

        let pair = try ServerOSKeyPair.from(seed: seed, comment: "test")
        XCTAssertEqual(
            pair.publicKeyAuthorizedKeysLine,
            SSHKeyFixtures.ed25519PublicKey + " test"
        )

        let line = try parsed.publicKeyAuthorizedKeysLine(comment: "test")
        XCTAssertEqual(line, SSHKeyFixtures.ed25519PublicKey + " test")
    }

    func testParsesAnECDSAP256Key() throws {
        let parsed = try OpenSSHKeyParser.parse(SSHKeyFixtures.p256PrivateKey)
        guard case .p256(let scalar) = parsed else {
            return XCTFail("expected a P-256 key, got \(parsed)")
        }
        XCTAssertEqual(scalar.count, 32)
        XCTAssertEqual(scalar, Data(base64Encoded: SSHKeyFixtures.p256ScalarBase64))

        let line = try parsed.publicKeyAuthorizedKeysLine(comment: "test")
        XCTAssertEqual(line, SSHKeyFixtures.p256PublicKey + " test")
    }

    func testParsesASEC1PEMKey() throws {
        let parsed = try OpenSSHKeyParser.parse(SSHKeyFixtures.p256SEC1PrivateKey)
        guard case .p256(let scalar) = parsed else {
            return XCTFail("expected a P-256 key, got \(parsed)")
        }
        XCTAssertEqual(scalar, Data(base64Encoded: SSHKeyFixtures.p256ScalarBase64))
    }

    func testParsedKeysBecomeNIOKeys() throws {
        XCTAssertNoThrow(try OpenSSHKeyParser.parse(SSHKeyFixtures.ed25519PrivateKey).nioPrivateKey())
        XCTAssertNoThrow(try OpenSSHKeyParser.parse(SSHKeyFixtures.p256PrivateKey).nioPrivateKey())
    }

    // MARK: - Keys that don't, and what we say about them

    func testAnEncryptedKeyExplainsBothWaysOut() {
        XCTAssertThrowsError(try OpenSSHKeyParser.parse(SSHKeyFixtures.ed25519EncryptedPrivateKey)) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_encrypted")
            XCTAssertTrue(
                error.causes.contains { $0.contains("ServerOS create its own key") },
                "the user must be told they can let ServerOS make a key: \(error.causes)"
            )
            XCTAssertTrue(
                error.causes.contains { $0.contains("ssh-keygen -p -f") },
                "the user must be told exactly how to strip the passphrase: \(error.causes)"
            )
            XCTAssertFalse(error.headline.hasSuffix("!"))
        }
    }

    func testAnRSAKeySaysPlainlyThatRSAIsNotSupported() {
        XCTAssertThrowsError(try OpenSSHKeyParser.parse(SSHKeyFixtures.rsaPrivateKey)) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_rsa_unsupported")
            XCTAssertTrue(error.headline.contains("RSA"))
            XCTAssertFalse(error.isRetryable, "retrying an RSA key will never work")
            XCTAssertTrue(
                error.causes.contains { $0.contains("ServerOS create its own key") },
                "an unusable key must come with a way forward: \(error.causes)"
            )
            XCTAssertTrue(error.causes.contains { $0.contains("ssh-keygen") })
        }
    }

    func testSomethingThatIsNotAKeyAtAll() {
        XCTAssertThrowsError(try OpenSSHKeyParser.parse("hello, I am a text file")) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_unusable")
        }
    }

    func testATruncatedContainerIsReportedAsDamagedNotAsUnsupported() {
        let truncated = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
        -----END OPENSSH PRIVATE KEY-----
        """
        XCTAssertThrowsError(try OpenSSHKeyParser.parse(truncated)) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_malformed")
            XCTAssertNotNil(error.technical, "an engineer needs to know which part was short")
        }
    }

    func testALegacyEncryptedPEMIsCaughtByItsHeader() {
        let legacy = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF

        aGVsbG8gdGhlcmU=
        -----END RSA PRIVATE KEY-----
        """
        XCTAssertThrowsError(try OpenSSHKeyParser.parse(legacy)) { error in
            XCTAssertEqual((error as? ServerOSError)?.code, "ssh_key_encrypted")
        }
    }

    func testAP521KeyIsRefusedByName() {
        // Built by hand: the container is well formed, the key type is one
        // ServerOS has no path for.
        let container = OpenSSHContainerBuilder.unencrypted(
            keyType: "ecdsa-sha2-nistp521",
            publicBlob: Data([1, 2, 3]),
            keyMaterial: SSHWire.string("nistp521"),
            comment: "someone@somewhere"
        )
        XCTAssertThrowsError(try OpenSSHKeyParser.parse(container)) { error in
            guard let error = error as? ServerOSError else { return XCTFail("wrong error type: \(error)") }
            XCTAssertEqual(error.code, "ssh_key_unsupported")
            XCTAssertTrue(error.headline.contains("nistp521"), "say which type: \(error.headline)")
        }
    }

    func testACommentAndPaddingDoNotConfuseTheParser() throws {
        // Real `ssh-keygen` keys carry a comment and are padded to the cipher
        // block size; the fixture above has an empty comment, so this covers
        // the other shape.
        let seed = try XCTUnwrap(Data(base64Encoded: SSHKeyFixtures.ed25519SeedBase64))
        let pair = try ServerOSKeyPair.from(seed: seed, comment: "orion@macbook")
        let material = SSHWire.string(pair.publicKeyBlob.suffix(32))
            + SSHWire.string(seed + pair.publicKeyBlob.suffix(32))

        let container = OpenSSHContainerBuilder.unencrypted(
            keyType: "ssh-ed25519",
            publicBlob: pair.publicKeyBlob,
            keyMaterial: material,
            comment: "orion@macbook"
        )

        let parsed = try OpenSSHKeyParser.parse(container)
        guard case .ed25519(let parsedSeed) = parsed else { return XCTFail("expected an Ed25519 key") }
        XCTAssertEqual(parsedSeed, seed)
    }
}

/// Builds openssh-key-v1 containers, so tests can cover shapes no local
/// `ssh-keygen` happens to produce.
enum OpenSSHContainerBuilder {

    static func unencrypted(
        keyType: String,
        publicBlob: Data,
        keyMaterial: Data,
        comment: String
    ) -> String {
        var privateSection = Data()
        privateSection.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])   // checkint
        privateSection.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])   // and again
        privateSection.append(SSHWire.string(keyType))
        privateSection.append(keyMaterial)
        privateSection.append(SSHWire.string(comment))

        // 1, 2, 3 … up to the cipher block size, which is 8 for "none".
        var padding: UInt8 = 1
        while privateSection.count % 8 != 0 {
            privateSection.append(padding)
            padding += 1
        }

        var body = Data("openssh-key-v1\u{0}".utf8)
        body.append(SSHWire.string("none"))
        body.append(SSHWire.string("none"))
        body.append(SSHWire.string(Data()))
        body.append(contentsOf: [0, 0, 0, 1])                          // one key
        body.append(SSHWire.string(publicBlob))
        body.append(SSHWire.string(privateSection))

        let base64 = body.base64EncodedString()
        var wrapped: [String] = []
        var index = base64.startIndex
        while index < base64.endIndex {
            let end = base64.index(index, offsetBy: 70, limitedBy: base64.endIndex) ?? base64.endIndex
            wrapped.append(String(base64[index..<end]))
            index = end
        }

        return (["-----BEGIN OPENSSH PRIVATE KEY-----"]
            + wrapped
            + ["-----END OPENSSH PRIVATE KEY-----"]).joined(separator: "\n")
    }
}
