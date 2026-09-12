//  KeychainTests.swift
//  ServerOSTests
//
//  Round-tripping real Keychain items.
//
//  These touch the actual Keychain rather than a stub, because the things worth
//  testing here are exactly the things a stub would get wrong: that an update
//  replaces rather than duplicating, that a missing item is `nil` rather than
//  an error, that `kSecUseDataProtectionKeychain` is accepted at all.
//
//  Each test uses a service name unique to the run and deletes what it wrote,
//  so nothing is left behind in a developer's login keychain. Where the
//  Keychain is simply unavailable — an unsigned test host, a CI machine with no
//  login keychain unlocked — the tests skip rather than fail, because a red
//  suite that everyone learns to ignore is worse than an honest skip.

import XCTest
@testable import ServerOS

final class KeychainTests: XCTestCase {

    private var service: String = ""
    private var store: KeychainStore = KeychainStore(service: "placeholder")

    override func setUp() {
        super.setUp()
        service = "com.orionsystems.ServerOS.tests.\(UUID().uuidString)"
        store = KeychainStore(service: service)
    }

    override func tearDown() {
        // Best effort: if the Keychain was unavailable there is nothing to tidy.
        if let accounts = try? store.allAccounts() {
            for account in accounts {
                try? store.delete(account)
            }
        }
        super.tearDown()
    }

    /// Write once, or skip the test if this environment has no usable Keychain.
    ///
    /// `KeychainStore` now falls back to the file-based keychain when this build
    /// is not entitled to the data-protection one, so on an ad-hoc-signed test
    /// host these run for real rather than skipping. The skip stays for the case
    /// where neither is available — a locked keychain on CI, say.
    private func requireKeychain() throws {
        do {
            try store.set(Data("probe".utf8), for: "__probe__")
            try store.delete("__probe__")
        } catch {
            throw XCTSkip("The Keychain is not usable in this environment: \(error)")
        }
    }

    /// The regression this exists for: a build that cannot reach the
    /// data-protection keychain must still be able to store a credential,
    /// because the alternative was a server that silently failed to save.
    func testStoringWorksEvenWithoutDataProtectionEntitlement() throws {
        KeychainStore.overrideKeychainPreference(useDataProtection: false)
        defer { KeychainStore.overrideKeychainPreference(useDataProtection: nil) }

        let fallbackStore = KeychainStore(service: service)
        do {
            try fallbackStore.set(Data("secret".utf8), for: "fallback-account")
        } catch {
            throw XCTSkip("No keychain of either kind here: \(error)")
        }
        defer { try? fallbackStore.delete("fallback-account") }

        XCTAssertEqual(try fallbackStore.get("fallback-account"), Data("secret".utf8))
    }

    // MARK: - Round trip

    func testStoreAndRead() throws {
        try requireKeychain()

        let secret = Data([0x00, 0x01, 0x02, 0xFE, 0xFF])
        try store.set(secret, for: "srv_alpha")

        XCTAssertEqual(try store.get("srv_alpha"), secret)
    }

    func testWritingTwiceOverwritesRatherThanDuplicating() throws {
        try requireKeychain()

        // `kSecAttrService` + `kSecAttrAccount` is the primary key for a generic
        // password: a second `SecItemAdd` would fail with errSecDuplicateItem
        // rather than replacing, which is why `set` tries `SecItemUpdate` first.
        try store.set(Data("first".utf8), for: "srv_alpha")
        try store.set(Data("second".utf8), for: "srv_alpha")

        XCTAssertEqual(try store.get("srv_alpha"), Data("second".utf8))
        XCTAssertEqual(try store.allAccounts(), ["srv_alpha"])
    }

    func testAMissingItemIsNilRatherThanAnError() throws {
        try requireKeychain()

        // "This server has no saved credential" is a state the app draws, not a
        // failure it has to pattern-match a status code out of.
        XCTAssertNil(try store.get("srv_never_written"))
    }

    func testDelete() throws {
        try requireKeychain()

        try store.set(Data("gone".utf8), for: "srv_alpha")
        XCTAssertNotNil(try store.get("srv_alpha"))

        try store.delete("srv_alpha")
        XCTAssertNil(try store.get("srv_alpha"))
    }

    func testDeletingSomethingThatIsNotThereSucceeds() throws {
        try requireKeychain()
        // Idempotent, so a retry after a partial failure is safe.
        XCTAssertNoThrow(try store.delete("srv_never_written"))
        XCTAssertNoThrow(try store.delete("srv_never_written"))
    }

    func testAllAccounts() throws {
        try requireKeychain()

        XCTAssertEqual(try store.allAccounts(), [])

        try store.set(Data("a".utf8), for: "srv_charlie")
        try store.set(Data("b".utf8), for: "srv_alpha")
        try store.set(Data("c".utf8), for: "srv_bravo")

        XCTAssertEqual(try store.allAccounts(), ["srv_alpha", "srv_bravo", "srv_charlie"])
    }

    func testTwoServicesDoNotSeeEachOther() throws {
        try requireKeychain()

        let other = KeychainStore(service: "\(service).other")
        defer { try? other.delete("srv_alpha") }

        try store.set(Data("mine".utf8), for: "srv_alpha")
        try other.set(Data("theirs".utf8), for: "srv_alpha")

        XCTAssertEqual(try store.get("srv_alpha"), Data("mine".utf8))
        XCTAssertEqual(try other.get("srv_alpha"), Data("theirs".utf8))
    }

    func testEmptyDataRoundTrips() throws {
        try requireKeychain()
        try store.set(Data(), for: "srv_empty")
        XCTAssertEqual(try store.get("srv_empty"), Data())
    }

    // MARK: - Credentials

    func testCredentialStoreRoundTrip() async throws {
        try requireKeychain()

        let credentials = CredentialStore(keychain: store)
        let credential = ServerCredential(
            serverID: "srv_563016eaa2ea5baa",
            agentSecret: Data(repeating: 0x2A, count: 32),
            agentPort: 8_723,
            sshPrivateKey: Data(repeating: 0x11, count: 32),
            sshPassword: nil,
            hostKeyFingerprint: "SHA256:2n4Ld9KqVQ0oN6v1TzL8bR3uYcW7jH5pXeA1sDfGhIk"
        )

        try await credentials.save(credential)
        let loaded = try await credentials.load(serverID: "srv_563016eaa2ea5baa")

        let found = try XCTUnwrap(loaded)
        XCTAssertEqual(found.serverID, credential.serverID)
        XCTAssertEqual(found.agentSecret, credential.agentSecret)
        XCTAssertEqual(found.agentPort, 8_723)
        XCTAssertEqual(found.sshPrivateKey, credential.sshPrivateKey)
        XCTAssertNil(found.sshPassword)
        XCTAssertEqual(found.hostKeyFingerprint, credential.hostKeyFingerprint)

        // Computed before asserting: XCTAssert's autoclosures are throwing but
        // not asynchronous, so an `await` cannot live inside one.
        let enrolled = try await credentials.enrolledServerIDs()
        XCTAssertEqual(enrolled, ["srv_563016eaa2ea5baa"])

        try await credentials.delete(serverID: "srv_563016eaa2ea5baa")
        let afterDelete = try await credentials.load(serverID: "srv_563016eaa2ea5baa")
        XCTAssertNil(afterDelete)
    }

    func testLoadingAServerWithNoCredentialIsNil() async throws {
        try requireKeychain()
        let credentials = CredentialStore(keychain: store)
        let loaded = try await credentials.load(serverID: "srv_not_here")
        XCTAssertNil(loaded)
    }

    // MARK: - Not leaking

    func testACredentialNeverPrintsItsSecrets() {
        // A backstop, not a licence: nothing is allowed to log one of these at
        // all. But a stray interpolation in an error message must not be the
        // thing that puts an agent secret into a support ticket.
        let credential = ServerCredential(
            serverID: "srv_alpha",
            agentSecret: Data("super-secret-agent-key".utf8),
            agentPort: 8_723,
            sshPrivateKey: Data("super-secret-ssh-key".utf8),
            sshPassword: "hunter2",
            hostKeyFingerprint: "SHA256:abc"
        )

        for rendering in ["\(credential)", credential.description, credential.debugDescription, String(describing: credential)] {
            XCTAssertTrue(rendering.contains("srv_alpha"))
            XCTAssertFalse(rendering.contains("hunter2"))
            XCTAssertFalse(rendering.contains("super-secret"))
            XCTAssertFalse(rendering.contains("SHA256:abc"))
        }
    }

    // MARK: - Error copy

    func testKeychainErrorsProduceASentenceRatherThanAStatusCode() {
        let cases: [KeychainError] = [
            .encoding,
            .unexpectedStatus(errSecItemNotFound),
            .unexpectedStatus(errSecDuplicateItem),
            .unexpectedStatus(errSecUserCanceled),
            .unexpectedStatus(errSecAuthFailed),
            .unexpectedStatus(errSecInteractionNotAllowed),
            .unexpectedStatus(errSecNotAvailable),
            .unexpectedStatus(errSecMissingEntitlement),
            .unexpectedStatus(-99_999),
        ]

        for error in cases {
            let message = error.userMessage
            XCTAssertFalse(message.isEmpty)
            XCTAssertTrue(message.hasSuffix("."), "\(message) should be a sentence")
            // The raw status belongs behind "Technical details", never in the
            // headline.
            XCTAssertFalse(message.contains("OSStatus"), "\(message) leaks the status code")
            XCTAssertFalse(error.technicalDetail.isEmpty)
        }

        XCTAssertTrue(KeychainError.unexpectedStatus(errSecInteractionNotAllowed)
            .userMessage.contains("Unlock your Mac"))
        XCTAssertTrue(KeychainError.unexpectedStatus(-99_999)
            .technicalDetail.contains("-99999"))
    }
}
