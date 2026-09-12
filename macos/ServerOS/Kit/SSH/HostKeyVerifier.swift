//  HostKeyVerifier.swift
//  ServerOS
//
//  Deciding whether the machine that answered is the machine we meant.
//
//  ──────────────────────────────────────────────────────────────────────────
//  WHY THIS FILE IS NOT `validationCompletePromise.succeed(())`
//
//  swift-nio-ssh ships an `AcceptAllHostKeysDelegate` in its sample client with
//  the comment "Do not replicate this in your own code". The reason is worth
//  spelling out, because a delegate that always succeeds *looks* like it works:
//  connections succeed, commands run, the product demos fine.
//
//  SSH's encryption protects the session from being read or altered by someone
//  in the middle. It does not, by itself, tell you who is on the other end —
//  that is the host key's job. A client that accepts any host key will happily
//  complete a perfectly encrypted session with an attacker who redirected the
//  connection, hand over the user's password or let them watch every command,
//  and report a healthy green dot while doing it.
//
//  Everything else in this SSH layer — the agent secret that crosses the wire
//  exactly once during enrollment, the Keychain, the signed requests — is
//  built on the assumption that the far end is the server the user chose. If
//  host keys are not checked, none of that holds and the whole layer is
//  decorative. So: trust on first use, pin, and refuse on change.
//  ──────────────────────────────────────────────────────────────────────────
//
//  Trust on first use is a real compromise, and it is the same one OpenSSH
//  makes. The first connection cannot be verified without out-of-band
//  information the user usually doesn't have, so ServerOS accepts it, records
//  the key, and shows the fingerprint so a careful user can compare it against
//  their hosting panel. Every connection after that is checked, and a change is
//  a hard stop — never a warning the user can click through by habit.

import Foundation
import NIOCore
import NIOSSH

/// Validates the server's host key: trust on first use, then pin.
///
/// A `final class` with a lock rather than an actor because swift-nio-ssh calls
/// `validateHostKey` synchronously on the connection's event loop, and because
/// the value has to be captured by the `@Sendable` channel initialiser.
public final class HostKeyVerifier: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {

    /// What the caller pinned, if anything. Either an OpenSSH public key line
    /// (`"ssh-ed25519 AAAA…"`) or a `"SHA256:…"` fingerprint — `ServerCredential`
    /// stores the fingerprint form, the Add Server flow has the full line.
    private let pinnedHostKey: String?

    private let lock = NSLock()
    private var _observedHostKey: String?
    private var _observedFingerprint: String?
    private var _mismatch: ServerOSError?

    public init(pinnedHostKey: String?) {
        let trimmed = pinnedHostKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.pinnedHostKey = (trimmed?.isEmpty ?? true) ? nil : trimmed
    }

    /// The key the server actually presented, in canonical
    /// `"<algorithm> <base64>"` form. `nil` until a connection has been
    /// attempted. This is the value to persist after a first connection.
    public var observedHostKey: String? {
        lock.lock()
        defer { lock.unlock() }
        return _observedHostKey
    }

    /// The same key as `"SHA256:…"`, which is what to show a person.
    public var observedFingerprint: String? {
        lock.lock()
        defer { lock.unlock() }
        return _observedFingerprint
    }

    /// Set when the presented key did not match the pinned one.
    ///
    /// The failure is recorded here as well as pushed into the promise because
    /// an error travelling out through the pipeline can be overtaken by the
    /// channel closing, and "the identity of this server changed" is far too
    /// important a message to lose to a race.
    public var mismatch: ServerOSError? {
        lock.lock()
        defer { lock.unlock() }
        return _mismatch
    }

    /// Whether this connection was a first meeting, i.e. nothing was pinned.
    public var isFirstUse: Bool { pinnedHostKey == nil }

    // MARK: - NIOSSHClientServerAuthenticationDelegate

    public func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // `String(openSSHPublicKey:)` is the canonical, comment-free
        // "<algorithm-id> <base64>" form, and the only textual representation
        // swift-nio-ssh 0.15.0 offers. There is no `fingerprint` member.
        let presented = String(openSSHPublicKey: hostKey)
        let presentedFingerprint = SSHFingerprint.sha256(ofOpenSSHPublicKey: presented) ?? presented

        lock.lock()
        _observedHostKey = presented
        _observedFingerprint = presentedFingerprint
        let pinned = pinnedHostKey
        lock.unlock()

        guard let pinned else {
            // First meeting. Accept, having recorded the key so the caller can
            // store it and show it.
            validationCompletePromise.succeed(())
            return
        }

        if Self.matches(pinned: pinned, presented: presented, presentedFingerprint: presentedFingerprint) {
            validationCompletePromise.succeed(())
            return
        }

        let expected = pinned.hasPrefix("SHA256:")
            ? pinned
            : (SSHFingerprint.sha256(ofOpenSSHPublicKey: pinned) ?? pinned)
        let error = ServerOSError.hostKeyChanged(expected: expected, actual: presentedFingerprint)

        lock.lock()
        _mismatch = error
        lock.unlock()

        validationCompletePromise.fail(error)
    }

    // MARK: - Comparison

    /// Pure, so it can be tested without a connection.
    ///
    /// Two accepted forms for the pinned value, because two parts of the app
    /// hold it in two shapes:
    ///
    ///   * `"SHA256:…"`      — what `ServerCredential` stores
    ///   * `"ssh-ed25519 …"` — what the Add Server flow just observed
    ///
    /// The key line is compared in canonical form rather than literally, so a
    /// stored line that still carries a trailing comment matches.
    public static func matches(pinned: String, presented: String, presentedFingerprint: String) -> Bool {
        let pinned = pinned.trimmingCharacters(in: .whitespacesAndNewlines)

        if pinned.hasPrefix("SHA256:") {
            return pinned == presentedFingerprint
        }

        if let parsed = try? NIOSSHPublicKey(openSSHPublicKey: pinned) {
            return String(openSSHPublicKey: parsed) == presented
        }

        // Unparseable pinned value: fall back to comparing the first two
        // fields, which drops any comment. Never fall back to "accept".
        func canonical(_ line: String) -> String {
            line.split(whereSeparator: { $0.isWhitespace }).prefix(2).joined(separator: " ")
        }
        return canonical(pinned) == canonical(presented)
    }
}
