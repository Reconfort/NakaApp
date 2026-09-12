//  AgentToken.swift
//  ServerOS
//
//  Minting the credential the agent verifies.
//
//  The format, which `agent/crates/agent/src/auth.rs` is the authority on:
//
//      serveros.<base64url(payload)>.<base64url(HMAC-SHA256(secret, signingInput))>
//
//  where `signingInput` is the literal string `"serveros." + payloadBase64` and
//  the payload is compact JSON:
//
//      {"sub":"Abebe's MacBook Pro","iat":1789210483,"exp":1789210603,
//       "jti":"3Qk…","scp":"read write"}
//
//  Base64url is unpadded in all three positions — `Data.base64EncodedString()`
//  produces the standard alphabet *with* padding, so the encoder below is
//  written by hand rather than patched up after the fact.
//
//  # Three properties that are load-bearing
//
//  * **The secret never crosses the wire.** What travels is a signature over a
//    payload, so a captured request cannot be replayed into a durable
//    credential.
//  * **Every token is single-use.** The agent remembers recent `jti` values and
//    refuses a repeat. Caching a minted token — even for a second, even for a
//    retry — turns the next request into an `auth_replayed` failure. Mint one
//    per request, always.
//  * **Lifetime is capped at 300 seconds** by the agent (`MAX_TOKEN_LIFETIME_SECS`),
//    which rejects anything longer outright rather than trimming it. The
//    minter clamps so a caller cannot accidentally ask for a token that is
//    refused on arrival.

import CryptoKit
import Foundation

/// What a token is allowed to do, in the agent's own vocabulary.
///
/// The agent treats these as ordered — admin implies write implies read — so a
/// token minted with `[.read, .write]` satisfies a route that needs `read`.
public enum AgentScope: String, Sendable, CaseIterable, Comparable {
    /// Read state: metrics, listings, logs, file contents.
    case read
    /// Change state: restart a container, write a file, create a user.
    case write
    /// Irreversible or security-sensitive: delete a user, reveal masked
    /// environment variables, remove a container.
    case admin

    /// Severity order, matching the agent's `Scope` enum.
    private var rank: Int {
        switch self {
        case .read: return 0
        case .write: return 1
        case .admin: return 2
        }
    }

    public static func < (lhs: AgentScope, rhs: AgentScope) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// Mints short-lived, single-use request tokens for one server.
///
/// Holds the server's shared secret, so it is subject to every rule in
/// `ServerCredential.swift`: never logged, never persisted anywhere but the
/// Keychain.
public struct AgentTokenMinter: Sendable {

    /// The one and only token prefix the agent recognises.
    public static let prefix: String = "serveros"

    /// The longest lifetime the agent will accept, in seconds.
    public static let maximumLifetime: TimeInterval = 300

    /// The shortest lifetime worth minting. Below this, ordinary clock drift
    /// between Mac and server starts to matter more than the token does.
    public static let minimumLifetime: TimeInterval = 30

    /// What the app asks for by default: long enough to survive a slow request
    /// through a tunnel, short enough to be worthless if captured.
    public static let defaultLifetime: TimeInterval = 120

    private let secret: Data
    private let subject: String

    /// Create a minter for one server.
    ///
    /// - Parameters:
    ///   - secret: The 32-byte enrollment secret. Never leaves this type.
    ///   - subject: Who is asking, for the server's audit feed. Defaults to the
    ///     Mac's name, which is what makes "who restarted production" answerable.
    public init(secret: Data, subject: String = AgentTokenMinter.defaultSubject()) {
        self.secret = secret
        self.subject = AgentTokenMinter.sanitisedSubject(subject)
    }

    /// Mint one token.
    ///
    /// Call this once per request. The result is valid for `lifetime` seconds
    /// and for exactly one request — the agent refuses a second use.
    ///
    /// - Parameters:
    ///   - scopes: What this request needs. Empty is treated as `[.read]`.
    ///   - lifetime: Seconds of validity, clamped to the agent's limits.
    public func mint(scopes: [AgentScope], lifetime: TimeInterval = AgentTokenMinter.defaultLifetime) -> String {
        let now = Int64(Date().timeIntervalSince1970)
        let clamped = min(max(lifetime, AgentTokenMinter.minimumLifetime), AgentTokenMinter.maximumLifetime)
        let expiry = now + Int64(clamped.rounded())

        let payload = AgentTokenMinter.payloadJSON(
            subject: subject,
            issuedAt: now,
            expiresAt: expiry,
            tokenID: AgentTokenMinter.newTokenID(),
            scopes: scopes
        )

        let payloadB64 = AgentTokenMinter.base64URLEncode(Data(payload.utf8))
        let signingInput = "\(AgentTokenMinter.prefix).\(payloadB64)"
        let signature = HMAC<SHA256>.authenticationCode(
            for: Data(signingInput.utf8),
            using: SymmetricKey(data: secret)
        )
        return "\(signingInput).\(AgentTokenMinter.base64URLEncode(Data(signature)))"
    }

    // MARK: - Subject

    /// This Mac's name, as the server's audit feed should show it.
    public static func defaultSubject() -> String {
        if let name = Host.current().localizedName, !name.trimmingCharacters(in: .whitespaces).isEmpty {
            return name
        }
        return "ServerOS for Mac"
    }

    /// Reduce a subject to characters that need no JSON escaping.
    ///
    /// The payload below is assembled as text rather than run through
    /// `JSONEncoder`, so that minting cannot throw and so that a test can
    /// predict the exact bytes that get signed. That is only safe if the one
    /// free-form field cannot contain a quote, a backslash or a control
    /// character — hence this. A Mac called `"Bob's" \Mac` becomes
    /// `Bob's -Mac`, which is a cosmetic loss in an audit line and nothing more.
    static func sanitisedSubject(_ raw: String) -> String {
        var out = ""
        out.reserveCapacity(raw.count)
        for character in raw {
            if character.isLetter || character.isNumber {
                out.append(character)
            } else if character == " " || character == "-" || character == "_" || character == "." || character == "'" {
                out.append(character)
            } else {
                out.append("-")
            }
        }
        let trimmed = out.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            return "ServerOS for Mac"
        }
        return String(trimmed.prefix(64))
    }

    // MARK: - Payload

    /// The compact JSON the agent parses, in the same field order its own
    /// minter writes. Order is cosmetic — the agent parses JSON — but matching
    /// it makes the two implementations diffable by eye.
    static func payloadJSON(
        subject: String,
        issuedAt: Int64,
        expiresAt: Int64,
        tokenID: String,
        scopes: [AgentScope]
    ) -> String {
        let effective: [AgentScope] = scopes.isEmpty ? [.read] : scopes
        var seen: [AgentScope] = []
        for scope in effective.sorted() where !seen.contains(scope) {
            seen.append(scope)
        }
        let scopeText = seen.map { $0.rawValue }.joined(separator: " ")
        return "{\"sub\":\"\(subject)\",\"iat\":\(issuedAt),\"exp\":\(expiresAt),\"jti\":\"\(tokenID)\",\"scp\":\"\(scopeText)\"}"
    }

    /// 16 random bytes, base64url. Unique per token — this is what the agent's
    /// replay cache keys on.
    static func newTokenID() -> String {
        var generator = SystemRandomNumberGenerator()
        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for _ in 0..<16 {
            bytes.append(UInt8.random(in: UInt8.min...UInt8.max, using: &generator))
        }
        return base64URLEncode(Data(bytes))
    }

    // MARK: - Base64url

    /// RFC 4648 §5, unpadded. Foundation only offers padded standard base64.
    public static func base64URLEncode(_ data: Data) -> String {
        var text = data.base64EncodedString()
        text = text.replacingOccurrences(of: "+", with: "-")
        text = text.replacingOccurrences(of: "/", with: "_")
        while text.hasSuffix("=") {
            text.removeLast()
        }
        return text
    }

    /// The inverse, tolerant of missing padding. Used by the tests to read back
    /// a payload, and available to anything that needs to inspect a token.
    public static func base64URLDecode(_ text: String) -> Data? {
        var standard = text.replacingOccurrences(of: "-", with: "+")
        standard = standard.replacingOccurrences(of: "_", with: "/")
        let remainder = standard.count % 4
        if remainder == 2 {
            standard += "=="
        } else if remainder == 3 {
            standard += "="
        } else if remainder == 1 {
            return nil
        }
        return Data(base64Encoded: standard)
    }
}
