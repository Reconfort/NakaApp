//  ServerCredential.swift
//  ServerOS
//
//  Everything secret about one server, and the only door to it.
//
//  ──────────────────────────────────────────────────────────────────────────
//  THE RULE
//
//  A `ServerCredential` may exist in exactly two places: inside the macOS
//  Keychain, and briefly in memory while a request is being signed.
//
//  It must never be:
//
//      * written to `UserDefaults`, a plist, or any SwiftData model —
//        SwiftData's store is an ordinary unencrypted file;
//      * printed, logged, or included in an `os_log` argument;
//      * attached to an analytics event or a crash report;
//      * sent to the control plane, which deliberately never learns a server's
//        agent secret: the whole point of enrollment is that the secret is
//        generated on the server and shared only with this Mac;
//      * put into a SwiftUI `@State`, an error's `technical` field, or any
//        other value that ends up in a diagnostic dump.
//
//  `description` and `debugDescription` below print only the server id, so even
//  a stray `print(credential)` or a `"\(credential)"` in an error message leaks
//  nothing. That is a backstop, not a licence — none of the above is allowed.
//  ──────────────────────────────────────────────────────────────────────────

import Foundation

/// Everything secret about one server. Lives ONLY in the Keychain.
public struct ServerCredential: Codable, Sendable {

    /// The agent's own identity for this server, e.g. `srv_563016eaa2ea5baa`.
    /// Not a secret — it is the keychain account name — but it is what ties the
    /// secret below to a `ServerRecord`.
    public let serverID: String

    /// The 32-byte shared secret from the enrollment bundle.
    ///
    /// Never transmitted. Requests carry an HMAC over a short-lived payload
    /// instead, so capturing one request buys an attacker nothing.
    public let agentSecret: Data

    /// The port the agent listens on, on the *server* side of the SSH tunnel.
    public let agentPort: Int

    /// The raw Ed25519 seed ServerOS generated for this server, when ServerOS
    /// manages the key itself. `nil` when the user brought their own agent or
    /// chose password authentication.
    public let sshPrivateKey: Data?

    /// Only present if the user chose password authentication. Storing this is
    /// a concession to real-world servers, not a recommendation.
    public let sshPassword: String?

    /// The host key ServerOS saw the first time it connected, as
    /// `SHA256:base64`. A mismatch on a later connection is
    /// `ServerOSError.hostKeyChanged` and stops the connection dead.
    public let hostKeyFingerprint: String?

    /// Create a credential. Every field is immutable; changing one means
    /// writing a new credential over the old.
    public init(
        serverID: String,
        agentSecret: Data,
        agentPort: Int,
        sshPrivateKey: Data? = nil,
        sshPassword: String? = nil,
        hostKeyFingerprint: String? = nil
    ) {
        self.serverID = serverID
        self.agentSecret = agentSecret
        self.agentPort = agentPort
        self.sshPrivateKey = sshPrivateKey
        self.sshPassword = sshPassword
        self.hostKeyFingerprint = hostKeyFingerprint
    }
}

extension ServerCredential: CustomStringConvertible, CustomDebugStringConvertible {
    /// Deliberately says nothing. See the file comment.
    public var description: String {
        "ServerCredential(serverID: \(serverID), secrets withheld)"
    }

    /// Deliberately says nothing, including in the debugger's variables view
    /// and in `dump(_:)`.
    public var debugDescription: String {
        description
    }
}

// MARK: - Storage

/// The app's one route to saved server secrets.
///
/// An actor because `SecItem*` blocks its calling thread and because every
/// caller is already `async` — the connection flow, the token minter and the
/// settings screen all reach it from a `Task`.
public actor CredentialStore {

    /// The keychain service every ServerOS credential lives under.
    public static let defaultService: String = "com.orionsystems.ServerOS.credentials"

    private let keychain: KeychainStore
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// Create a store, optionally over a different keychain service (tests do).
    public init(keychain: KeychainStore = KeychainStore(service: CredentialStore.defaultService)) {
        self.keychain = keychain
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
    }

    /// Write a credential, replacing any credential already held for that
    /// server.
    public func save(_ credential: ServerCredential) throws {
        let data = try encoder.encode(credential)
        try keychain.set(data, for: credential.serverID)
    }

    /// The credential for one server, or `nil` when the Mac has none.
    ///
    /// `nil` is the ordinary "this server was never set up here, or its item
    /// was removed" case; callers turn it into `ServerOSError.noCredential`
    /// rather than treating it as a crash.
    public func load(serverID: String) throws -> ServerCredential? {
        guard let data = try keychain.get(serverID) else {
            return nil
        }
        return try decoder.decode(ServerCredential.self, from: data)
    }

    /// Forget a server's secrets. Idempotent.
    public func delete(serverID: String) throws {
        try keychain.delete(serverID)
    }

    /// Every server this Mac holds a credential for.
    ///
    /// The keychain, not the local database, is the source of truth for "am I
    /// enrolled": a restored-from-backup Mac can have server rows with no
    /// secrets, and the app must show those as needing setup rather than
    /// failing every request against them.
    public func enrolledServerIDs() throws -> [String] {
        try keychain.allAccounts()
    }
}
