//  ServerPersistenceTests.swift
//  ServerOSTests
//
//  A server was added successfully — the agent installed, started, and reported
//  back — and then did not appear in the server list. The record was never
//  written, because saving its credential threw first and the caller discarded
//  the error with `try?`. Setup said "Prod is set up", the list said "0 servers",
//  and nothing in between said anything at all.
//
//  Two failures, one visible and one not:
//
//    * the Keychain refused every write, because the app asked for a
//      `keychain-access-groups` entitlement it could not be granted; and
//    * the one line of code that would have said so threw the error away.
//
//  The second is the one that made it a mystery. These tests hold the line on
//  both: that a server survives being written down, that it survives the app
//  being closed, and that a failure to save is never silent.

import SwiftData
import XCTest
@testable import ServerOS

final class ServerPersistenceTests: XCTestCase {

    private var storeURL: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        storeURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("serveros-tests-\(UUID().uuidString)")
            .appendingPathExtension("store")
    }

    override func tearDownWithError() throws {
        // SwiftData writes siblings (-wal, -shm); clear them too.
        let directory = storeURL.deletingLastPathComponent()
        let prefix = storeURL.lastPathComponent
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil)) ?? []
        for url in contents where url.lastPathComponent.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: url)
        }
        try super.tearDownWithError()
    }

    /// A store backed by a real file, so "still there after a relaunch" means
    /// what it says. An in-memory container would pass this test while the
    /// product remained broken.
    private func makeStore() throws -> ServerStore {
        let schema = Schema([ServerRecord.self])
        let configuration = ModelConfiguration(schema: schema, url: storeURL)
        return ServerStore(container: try ModelContainer(for: schema, configurations: [configuration]))
    }

    private func prod() -> ServerSummary {
        // The server from the report, with the metadata setup actually collected.
        ServerSummary(
            id: "srv_8809a5eebdd4fc9",
            name: "Prod",
            hostname: "198.51.100.20",
            sshPort: 22,
            sshUsername: "root",
            agentPort: 8723,
            osPretty: "Ubuntu 24.04.4 LTS",
            arch: "x86_64",
            lastSeenAt: Date(timeIntervalSince1970: 1_789_000_000),
            addedAt: Date(timeIntervalSince1970: 1_789_000_000),
            tags: [],
            sortIndex: 0,
            isDemo: false
        )
    }

    // MARK: - The reported bug

    func testAServerIsStillThereAfterNavigatingAwayAndReloading() async throws {
        let store = try makeStore()
        try await store.upsert(prod())

        // What the Servers screen does: ask the same store again.
        let reloaded = try await store.all()

        XCTAssertEqual(reloaded.count, 1, "the server list came back empty")
        XCTAssertEqual(reloaded.first?.name, "Prod")
        XCTAssertEqual(reloaded.first?.id, "srv_8809a5eebdd4fc9")
    }

    func testAServerSurvivesTheAppBeingClosedAndReopened() async throws {
        // Write with one container...
        let first = try makeStore()
        try await first.upsert(prod())

        // ...then throw it away, exactly as quitting the app does, and open the
        // same file again the way the next launch will.
        let second = try makeStore()
        let afterRelaunch = try await second.all()

        XCTAssertEqual(afterRelaunch.count, 1,
                       "the server did not survive a relaunch — the store is not durable")
        XCTAssertEqual(afterRelaunch.first?.name, "Prod")
    }

    func testTheMetadataSetupCollectedIsSavedWithTheServer() async throws {
        // The setup screen showed these. If they are not persisted, the server
        // detail screen has to re-derive them or show blanks.
        let store = try makeStore()
        try await store.upsert(prod())

        let all = try await store.all()
        let saved = try XCTUnwrap(all.first)
        XCTAssertEqual(saved.osPretty, "Ubuntu 24.04.4 LTS")
        XCTAssertEqual(saved.arch, "x86_64")
        XCTAssertEqual(saved.agentPort, 8723)
        XCTAssertEqual(saved.sshUsername, "root")
        XCTAssertEqual(saved.sshPort, 22)
        XCTAssertFalse(saved.isDemo)
    }

    func testSettingUpTheSameServerTwiceDoesNotDuplicateIt() async throws {
        // Setup is idempotent, and the error message for a failed save says so.
        // That promise is only true if the store upserts.
        let store = try makeStore()
        try await store.upsert(prod())
        try await store.upsert(prod())

        let count = try await store.all().count
        XCTAssertEqual(count, 1, "re-running setup duplicated the server")
    }

    func testRemovingAServerRemovesItFromDiskToo() async throws {
        let store = try makeStore()
        try await store.upsert(prod())
        try await store.delete(id: prod().id)

        let remaining = try await store.all()
        XCTAssertTrue(remaining.isEmpty)
        let afterRelaunch = try await makeStore().all()
        XCTAssertTrue(afterRelaunch.isEmpty, "it came back after a relaunch")
    }

    // MARK: - The failure that was swallowed

    func testAFailedSaveSaysTheServerItselfIsFine() {
        // The agent really is installed and running by this point. A message
        // that reads like setup failed would send the user to undo work that
        // succeeded, or to re-run setup fearing the server is half-configured.
        let error = ServerOSError.serverNotSaved(
            name: "Prod",
            underlying: KeychainError.unexpectedStatus(errSecMissingEntitlement)
        )

        XCTAssertTrue(error.headline.contains("Prod"), error.headline)
        XCTAssertTrue(
            error.causes.contains { $0.contains("installed and running") },
            "must say the server itself is fine: \(error.causes)"
        )
        XCTAssertTrue(
            error.causes.contains { $0.contains("safe") },
            "must say adding it again is safe: \(error.causes)"
        )
    }

    func testAKeychainEntitlementFailureIsNamedRatherThanShownAsANumber() {
        // "unexpectedStatus(-34018)" tells the user nothing they can act on.
        let error = ServerOSError.serverNotSaved(
            name: "Prod",
            underlying: KeychainError.unexpectedStatus(errSecMissingEntitlement)
        )

        XCTAssertTrue(
            error.causes.contains { $0.contains("code-signed") },
            "the real cause has to be named: \(error.causes)"
        )
        XCTAssertTrue(
            error.causes.contains { $0.lowercased().contains("xcode") },
            "and the way out of it: \(error.causes)"
        )
    }

    func testAnOrdinaryFailureDoesNotBlameCodeSigning() {
        // Only the entitlement case gets the signing advice; a disk-full error
        // must not send the user to Signing & Capabilities.
        struct DiskFull: Error {}
        let error = ServerOSError.serverNotSaved(name: "Prod", underlying: DiskFull())

        XCTAssertFalse(
            error.causes.contains { $0.contains("code-signed") },
            "\(error.causes)"
        )
        XCTAssertNotNil(error.technical, "the raw error is still available")
    }

    func testAFailedListChangeAdmitsTheScreenMayBeWrong() {
        let error = ServerOSError.listChangeFailed(
            what: "rename Prod",
            underlying: KeychainError.unexpectedStatus(errSecMissingEntitlement)
        )
        XCTAssertTrue(error.headline.contains("rename Prod"), error.headline)
        XCTAssertTrue(
            error.causes.contains { $0.contains("out of date") },
            "the user needs to know the screen is now lying: \(error.causes)"
        )
        XCTAssertTrue(error.isRetryable)
    }
}
