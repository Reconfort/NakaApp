//  Keychain.swift
//  ServerOS
//
//  The only place in the app that talks to `SecItem*`.
//
//  Two reasons this is a type rather than a handful of free functions:
//
//  * **Testability.** Everything above it takes a `KeychainStore`, so a test can
//    point one at a throwaway service name and leave the user's real items
//    alone. There is no global to stub.
//  * **Two macOS-specific details that are easy to get wrong and silent when
//    you do.** `kSecUseDataProtectionKeychain` must be set on *every* query or
//    macOS falls back to the legacy file keychain, where `kSecAttrAccessible`
//    is quietly ignored — the accessibility class you carefully chose does
//    nothing. And `kSecAttrService` + `kSecAttrAccount` are the primary key for
//    a generic password, so a second `SecItemAdd` with the same pair fails with
//    `errSecDuplicateItem` rather than overwriting. Both are handled here once,
//    so no caller has to remember them.
//
//  Accessibility is `kSecAttrAccessibleAfterFirstUnlock`: after a reboot the
//  Mac must be unlocked once, and from then on ServerOS can reconnect to a
//  server — reopen the tunnel, re-mint a token, resume the metrics stream —
//  while the screen is locked. `WhenUnlocked` would break every reconnection
//  the moment the display slept, which for an infrastructure monitor is the
//  precise moment it matters.
//
//  `SecItemAdd` blocks its thread. Nothing here is `@MainActor`, and the actor
//  that owns it (`CredentialStore`) keeps these calls off the main thread.

import Foundation
import Security

/// A thin, testable wrapper over the generic-password keychain.
///
/// One instance addresses one `kSecAttrService`; accounts within it are the
/// individual secrets.
public struct KeychainStore: Sendable {

    /// The `kSecAttrService` shared by every item this store reads or writes.
    public let service: String

    /// Create a store addressing one keychain service.
    ///
    /// - Parameter service: A reverse-DNS identifier, e.g.
    ///   `com.orionsystems.ServerOS.credentials`. Items written under one
    ///   service are invisible to a store created with another, which is how
    ///   tests stay out of the user's real keychain.
    public init(service: String) {
        self.service = service
    }

    // MARK: - Reading and writing

    /// Store `data` under `account`, replacing anything already there.
    ///
    /// Update-then-insert rather than delete-then-add: deleting first opens a
    /// window in which the credential does not exist at all, and a crash inside
    /// that window would log the user out of a server for no reason.
    public func set(_ data: Data, for account: String) throws {
        let query = baseQuery(account: account)
        let changes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(updateStatus)
        }

        var insert = query
        insert[kSecValueData as String] = data
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.unexpectedStatus(addStatus)
        }
    }

    /// The data stored under `account`, or `nil` when there is none.
    ///
    /// A missing item is an answer, not a failure: "this server has no saved
    /// credential" is a state the app draws, so it must not arrive as an error
    /// the caller has to pattern-match a status code out of.
    public func get(_ account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        guard let data = item as? Data else {
            throw KeychainError.encoding
        }
        return data
    }

    /// Remove `account` from this service. Deleting something that is not there
    /// succeeds, so a retry after a partial failure is safe.
    public func delete(_ account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        throw KeychainError.unexpectedStatus(status)
    }

    /// Every account name stored under this service, sorted.
    ///
    /// This is how the app answers "which servers am I actually enrolled with"
    /// without trusting a local database that could have drifted from the
    /// keychain.
    public func allAccounts() throws -> [String] {
        var query = baseQuery(account: nil)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        guard let attributes = items as? [[String: Any]] else {
            return []
        }

        let accountKey = kSecAttrAccount as String
        var accounts: [String] = []
        for entry in attributes {
            if let account = entry[accountKey] as? String {
                accounts.append(account)
            }
        }
        return accounts.sorted()
    }

    // MARK: - Query construction

    /// The attributes every query shares.
    ///
    /// `kSecUseDataProtectionKeychain` is not optional here — see the file
    /// comment. Without it `kSecAttrAccessible` below is ignored on macOS.
    private func baseQuery(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: Self.useDataProtectionKeychain,
        ]
        if let account {
            query[kSecAttrAccount as String] = account
        }
        return query
    }

    // MARK: - Which keychain

    /// The data-protection keychain is the right one: per-app isolation
    /// enforced by the system, no ACL prompts, the same API as iOS.
    ///
    /// It also requires the app to carry an application-identifier entitlement,
    /// which only a build signed with a real team has. A locally-built,
    /// ad-hoc-signed ServerOS gets `errSecMissingEntitlement` (-34018) on every
    /// single call — and that is not a hypothetical: it is what made a server
    /// that had just been set up fail to save, with no message, because the
    /// caller discarded the error.
    ///
    /// So: use the data-protection keychain, and fall back to the file-based
    /// keychain when this build cannot. The fallback is still the macOS
    /// Keychain — still encrypted, still per-user, still `SecItem` — it simply
    /// predates app-identity isolation. Refusing to store anything at all would
    /// not make a developer's Mac safer; it would just make the app unusable
    /// unless they happen to have an Apple developer account.
    ///
    /// Decided once, on first use, because the answer cannot change while the
    /// app is running.
    nonisolated(unsafe) private static var cachedPreference: Bool?
    private static let preferenceLock = NSLock()

    static var useDataProtectionKeychain: Bool {
        preferenceLock.lock()
        defer { preferenceLock.unlock() }
        if let cached = cachedPreference { return cached }
        let usable = probeDataProtectionKeychain()
        cachedPreference = usable
        return usable
    }

    /// Write and delete one throwaway item to find out whether this build is
    /// entitled to the data-protection keychain.
    private static func probeDataProtectionKeychain() -> Bool {
        let account = "__serveros_entitlement_probe__"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.orionsystems.ServerOS.probe",
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)

        var insert = query
        insert[kSecValueData as String] = Data("probe".utf8)
        let status = SecItemAdd(insert as CFDictionary, nil)
        SecItemDelete(query as CFDictionary)

        // Only a missing entitlement means "this build cannot use it". Any
        // other failure is a real problem that the fallback would only hide.
        return status != errSecMissingEntitlement
    }

    /// Force the choice, for tests that need to exercise one keychain or the
    /// other regardless of how the test host happens to be signed.
    static func overrideKeychainPreference(useDataProtection: Bool?) {
        preferenceLock.lock()
        cachedPreference = useDataProtection
        preferenceLock.unlock()
    }
}

// MARK: - Errors

/// Something the keychain refused to do.
public enum KeychainError: Error, Equatable, Sendable {
    /// `SecItem*` returned a status this code does not handle.
    case unexpectedStatus(OSStatus)
    /// An item came back in a shape that was not `Data`.
    case encoding

    /// One sentence, safe to show a person.
    ///
    /// The product rule is that `-25300` is never the headline. Each case that
    /// a user can actually cause gets its own wording; everything else falls
    /// back to a sentence that still says what failed and what to do about it.
    public var userMessage: String {
        switch self {
        case .encoding:
            return "ServerOS couldn't read a saved credential from your keychain."
        case .unexpectedStatus(let status):
            switch status {
            case errSecItemNotFound:
                return "That credential is no longer in your keychain."
            case errSecDuplicateItem:
                return "A credential for this server is already saved."
            case errSecUserCanceled:
                return "Keychain access was cancelled."
            case errSecAuthFailed:
                return "macOS wouldn't unlock the keychain for ServerOS."
            case errSecInteractionNotAllowed:
                return "Your keychain is locked. Unlock your Mac and try again."
            case errSecNotAvailable:
                return "Your keychain isn't available right now."
            case errSecMissingEntitlement:
                return "ServerOS isn't allowed to use the keychain on this Mac."
            default:
                return "ServerOS couldn't save to your keychain."
            }
        }
    }

    /// The raw detail, for the "Technical details" disclosure. Never the
    /// headline.
    public var technicalDetail: String {
        switch self {
        case .encoding:
            return "keychain item was not Data"
        case .unexpectedStatus(let status):
            if let text = SecCopyErrorMessageString(status, nil) as String? {
                return "OSStatus \(status): \(text)"
            }
            return "OSStatus \(status)"
        }
    }
}
