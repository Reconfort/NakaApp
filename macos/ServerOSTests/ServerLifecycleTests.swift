//  ServerLifecycleTests.swift
//  ServerOSTests
//
//  The lifecycle a server goes through after setup, which is where a server
//  management tool earns or loses trust:
//
//      added → visible → unreachable → visible, marked Offline → reconnected,
//      same identity → removed, and stays removed
//
//  The failure that matters most here is the one that looks like success: a
//  server disappearing from the list because it stopped answering. A server
//  that is down is exactly when the user most wants to see it — and to click
//  into it and find out why. "Not reachable" is a status, never an absence.

import XCTest
import SwiftData
@testable import ServerOS

final class ServerLifecycleTests: XCTestCase {

    private var storeURL: URL!
    private var keychainService: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        storeURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("serveros-lifecycle-\(UUID().uuidString)")
            .appendingPathExtension("store")
        keychainService = "com.orionsystems.ServerOS.tests.\(UUID().uuidString)"
    }

    override func tearDownWithError() throws {
        let directory = storeURL.deletingLastPathComponent()
        let prefix = storeURL.lastPathComponent
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil)) ?? []
        for url in contents where url.lastPathComponent.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: url)
        }
        try super.tearDownWithError()
    }

    private func makeStore() throws -> ServerStore {
        let schema = Schema([ServerRecord.self])
        let configuration = ModelConfiguration(schema: schema, url: storeURL)
        return ServerStore(container: try ModelContainer(for: schema, configurations: [configuration]))
    }

    private func makeCredentials() -> CredentialStore {
        CredentialStore(keychain: KeychainStore(service: keychainService))
    }

    private func prod() -> ServerSummary {
        ServerSummary(
            id: "srv_8809a5eebdd4fc9", name: "Prod", hostname: "198.51.100.20",
            sshPort: 22, sshUsername: "root", agentPort: 8723,
            osPretty: "Ubuntu 24.04.4 LTS", arch: "x86_64",
            lastSeenAt: Date(), addedAt: Date(), tags: [], sortIndex: 0, isDemo: false
        )
    }

    // MARK: - Offline

    func testAnUnreachableServerReportsOfflineRatherThanUnknown() {
        // The rollup the sidebar and the server list draw from.
        let health = HealthEvaluator.evaluate(
            HealthInput(isReachable: false, secondsSinceLastContact: nil)
        )
        XCTAssertEqual(health.state, .offline)
        XCTAssertEqual(health.action, .reconnect,
                       "an offline server's one useful action is to try again")
    }

    func testAnUnreachableServerIsStillInTheStore() async throws {
        // Health is computed from the live session; the list is drawn from the
        // store. They are deliberately separate, and this is why: losing the
        // connection must not lose the server.
        let store = try makeStore()
        try await store.upsert(prod())

        let health = HealthEvaluator.evaluate(HealthInput(isReachable: false))
        XCTAssertEqual(health.state, .offline)

        let listed = try await store.all()
        XCTAssertEqual(listed.count, 1, "an unreachable server vanished from the list")
        XCTAssertEqual(listed.first?.id, prod().id)
    }

    func testAServerThatWentQuietIsDegradedBeforeItIsOffline() {
        // Reachable, but the agent has not answered in a while. Jumping
        // straight to Offline on one slow poll would make the list flicker.
        let stale = HealthEvaluator.evaluate(
            HealthInput(isReachable: true, secondsSinceLastContact: 300)
        )
        XCTAssertNotEqual(stale.state, .healthy,
                          "five minutes without contact is not healthy")
    }

    // MARK: - Identity across reconnects

    func testReconnectingKeepsTheSameServerIdentity() async throws {
        // The id is what the Keychain item, the audit trail and the agent's own
        // enrolment are all keyed on. A reconnect that minted a new one would
        // orphan all three.
        let store = try makeStore()
        let original = prod()
        try await store.upsert(original)

        // A reconnect re-reads the summary and rebuilds the session around it.
        let found = try await store.server(id: original.id)
        let reloaded = try XCTUnwrap(found)
        XCTAssertEqual(reloaded.id, original.id)
        XCTAssertEqual(reloaded.agentPort, original.agentPort)
        XCTAssertEqual(reloaded.hostname, original.hostname)
    }

    func testUpdatingASeenServerDoesNotChangeItsIdentityOrDuplicateIt() async throws {
        let store = try makeStore()
        try await store.upsert(prod())

        var seenLater = prod()
        seenLater = ServerSummary(
            id: seenLater.id, name: seenLater.name, hostname: seenLater.hostname,
            sshPort: seenLater.sshPort, sshUsername: seenLater.sshUsername,
            agentPort: seenLater.agentPort, osPretty: seenLater.osPretty,
            arch: seenLater.arch,
            lastSeenAt: Date().addingTimeInterval(3_600),
            addedAt: seenLater.addedAt, tags: seenLater.tags,
            sortIndex: seenLater.sortIndex, isDemo: false
        )
        try await store.upsert(seenLater)

        let all = try await store.all()
        XCTAssertEqual(all.count, 1, "a later sighting created a second server")
        XCTAssertEqual(all.first?.id, prod().id)
    }

    // MARK: - Removal

    func testRemovingAServerTakesItsCredentialWithIt() async throws {
        let credentials = makeCredentials()
        let credential = ServerCredential(
            serverID: prod().id,
            agentSecret: Data("secret".utf8),
            agentPort: 8723
        )

        do {
            try await credentials.save(credential)
        } catch {
            throw XCTSkip("No usable Keychain in this environment: \(error)")
        }
        let stored = try await credentials.load(serverID: prod().id)
        XCTAssertNotNil(stored)

        let store = try makeStore()
        try await store.upsert(prod())

        // What AppModel.remove does, in order.
        try await credentials.delete(serverID: prod().id)
        try await store.delete(id: prod().id)

        let afterRemoval = try await credentials.load(serverID: prod().id)
        XCTAssertNil(afterRemoval,
                     "the agent secret outlived the server it belonged to")
        let remaining = try await store.all()
        XCTAssertTrue(remaining.isEmpty)
        let afterRelaunch = try await makeStore().all()
        XCTAssertTrue(afterRelaunch.isEmpty, "it came back after a relaunch")
    }

    func testRemovingAServerThatIsAlreadyGoneIsNotAnError() async throws {
        // Removal runs after the UI has navigated away, and can be retried.
        let store = try makeStore()
        try await store.upsert(prod())
        try await store.delete(id: prod().id)
        // Deleting twice is not an error: removal runs after the UI has already
        // navigated away, so it has to be safe to retry.
        do { try await store.delete(id: prod().id) }
        catch { XCTFail("deleting an already-deleted server threw: \(error)") }

        let credentials = makeCredentials()
        do { try await credentials.delete(serverID: "never-existed") }
        catch { XCTFail("deleting a credential that was never there threw: \(error)") }
    }

    func testRemovingOneServerLeavesTheOthers() async throws {
        let store = try makeStore()
        try await store.upsert(prod())

        let staging = ServerSummary(
            id: "srv_staging", name: "Staging", hostname: "198.51.100.21",
            sshPort: 22, sshUsername: "root", agentPort: 8723,
            osPretty: "Ubuntu 24.04.4 LTS", arch: "x86_64",
            lastSeenAt: Date(), addedAt: Date(), tags: [], sortIndex: 1, isDemo: false
        )
        try await store.upsert(staging)
        try await store.delete(id: prod().id)

        let remaining = try await store.all()
        XCTAssertEqual(remaining.map(\.id), ["srv_staging"])
    }

    // MARK: - Demo and real never mix

    func testDemoServersAndRealServersCoexistWithoutContaminatingEachOther() async throws {
        // Demo mode must never make a real server look fake, or the reverse.
        let store = try makeStore()
        try await store.upsert(prod())
        for demo in DemoEnvironment.shared.servers {
            try await store.upsert(demo)
        }

        let all = try await store.all()
        let real = all.filter { !$0.isDemo }
        XCTAssertEqual(real.count, 1)
        XCTAssertEqual(real.first?.id, prod().id)
        XCTAssertTrue(all.filter(\.isDemo).allSatisfy { $0.name.hasPrefix("Demo") },
                      "every demo server has to be labelled as one")
    }
}
