//  SSHKey.swift
//  ServerOS
//
//  The keypair ServerOS owns, and the wire format it is written in.
//
//  ServerOS prefers to bring its own identity to a server rather than borrow
//  the user's. A key generated here is Ed25519, lives in the Keychain as 32
//  bytes of seed, and is installed into `~/.ssh/authorized_keys` once, during
//  setup. The user's own key is still supported (see `OpenSSHKeyParser`), but
//  it is the second choice: a key ServerOS minted can be revoked by deleting
//  one line, without touching how the person logs in themselves.
//
//  Ed25519 and not RSA because swift-nio-ssh has no RSA support at all — not a
//  preference, an absolute. See `docs/reference/swift-nio-ssh-api.md`.
//
//  On `import Crypto`: `NIOSSHPrivateKey`'s initialisers are declared against
//  swift-crypto's `Crypto` module, which on Apple platforms is a re-export of
//  CryptoKit — `Crypto.Curve25519` and `CryptoKit.Curve25519` are the same
//  type. Importing `Crypto` is what makes the types line up with the library
//  we hand the key to.

import Foundation
import Crypto
import NIOSSH

// MARK: - SSH wire format

/// The encoding every SSH blob is made of.
///
/// RFC 4251 §5 defines exactly one composite type worth caring about here:
/// `string`, which is a 32-bit big-endian length followed by that many bytes.
/// A public key blob is nothing but two of those concatenated:
///
///     string  "ssh-ed25519"
///     string  <32 raw public key bytes>
///
/// base64 that, put the algorithm name in front of it, and you have the line
/// in `authorized_keys`. Small enough to write, and worth writing rather than
/// taking a dependency for.
public enum SSHWire {

    /// A `string`: four bytes of big-endian length, then the bytes.
    public static func string(_ bytes: Data) -> Data {
        // Callers pass key material — tens of bytes. The truncating conversion
        // is here so this function has no trapping path at all, not because a
        // 4 GB "string" is expected.
        let length = UInt32(truncatingIfNeeded: bytes.count)
        var out = Data()
        out.reserveCapacity(bytes.count + 4)
        out.append(UInt8(truncatingIfNeeded: length >> 24))
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(bytes)
        return out
    }

    /// A `string` holding UTF-8 text, which is how algorithm and curve names
    /// are written.
    public static func string(_ text: String) -> Data {
        string(Data(text.utf8))
    }

    /// The raw public key blob for an Ed25519 key: `string "ssh-ed25519"`
    /// followed by `string <raw key>`. This is the blob that gets base64'd into
    /// an `authorized_keys` line and the blob OpenSSH hashes for a fingerprint.
    public static func ed25519PublicKeyBlob(rawPublicKey: Data) -> Data {
        string(ed25519Algorithm) + string(rawPublicKey)
    }

    /// The algorithm identifier for an Ed25519 SSH key.
    public static let ed25519Algorithm = "ssh-ed25519"

    /// The algorithm identifier for a NIST P-256 SSH key.
    public static let p256Algorithm = "ecdsa-sha2-nistp256"
}

/// Reads the same format `SSHWire` writes.
///
/// Backed by `[UInt8]` rather than `Data` on purpose: a `Data` produced by
/// slicing does *not* start at index 0, and every SSH parser that forgets this
/// is one nasty bug waiting for a key that happens to be sliced.
public struct SSHWireReader {

    public enum ReadError: Error, Equatable {
        case truncated
        case tooLarge
        case notUTF8
    }

    private let bytes: [UInt8]
    private var offset: Int

    public init(_ data: Data) {
        self.bytes = Array(data)
        self.offset = 0
    }

    public init(bytes: [UInt8]) {
        self.bytes = bytes
        self.offset = 0
    }

    /// How many bytes are still unread.
    public var remainingCount: Int { bytes.count - offset }

    /// The bytes not yet read, left where they are.
    public var remaining: Data { Data(bytes[offset...]) }

    public mutating func readUInt32() throws -> UInt32 {
        guard remainingCount >= 4 else { throw ReadError.truncated }
        let value = UInt32(bytes[offset]) << 24
            | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8
            | UInt32(bytes[offset + 3])
        offset += 4
        return value
    }

    public mutating func readBytes(_ count: Int) throws -> Data {
        guard count >= 0, remainingCount >= count else { throw ReadError.truncated }
        let slice = bytes[offset..<(offset + count)]
        offset += count
        return Data(slice)
    }

    public mutating func readString() throws -> Data {
        let length = try readUInt32()
        // A length field larger than the buffer is either a truncated file or a
        // hostile one. Both get the same treatment.
        guard length <= UInt32(Int32.max) else { throw ReadError.tooLarge }
        return try readBytes(Int(length))
    }

    public mutating func readText() throws -> String {
        let data = try readString()
        guard let text = String(data: data, encoding: .utf8) else { throw ReadError.notUTF8 }
        return text
    }

    /// Reads a `mpint` (RFC 4251 §5) and normalises it to `width` bytes.
    ///
    /// OpenSSH writes EC private scalars as bignums, which means a leading
    /// `0x00` when the top bit is set, and fewer bytes than the curve width
    /// when the scalar happens to be small. CryptoKit wants exactly 32 bytes
    /// for P-256, so both cases have to be fixed up here.
    public mutating func readFixedWidthBignum(width: Int) throws -> Data {
        var value = Array(try readString())
        while value.first == 0 { value.removeFirst() }
        guard value.count <= width else { throw ReadError.tooLarge }
        return Data(repeating: 0, count: width - value.count) + Data(value)
    }
}

// MARK: - Fingerprints

/// The `SHA256:…` fingerprint format people recognise from `ssh-keygen -lf`
/// and from the prompt OpenSSH shows on a first connection.
///
/// swift-nio-ssh has no `fingerprint` member of its own — the whole of its
/// public key surface is `init(openSSHPublicKey:)`, `String(openSSHPublicKey:)`
/// and `Hashable`. So the fingerprint is derived here from the base64 blob in
/// the middle of an OpenSSH public key line, which is the same blob OpenSSH
/// hashes.
public enum SSHFingerprint {

    /// `SHA256:` followed by unpadded standard base64 of the digest.
    public static func sha256(ofBlob blob: Data) -> String {
        let digest = SHA256.hash(data: blob)
        let bytes = digest.withUnsafeBytes { Data($0) }
        return "SHA256:" + unpadded(bytes.base64EncodedString())
    }

    /// The fingerprint of an OpenSSH public key line
    /// (`"ssh-ed25519 AAAA… comment"`). `nil` if the line is not one.
    public static func sha256(ofOpenSSHPublicKey line: String) -> String? {
        guard let blob = blob(ofOpenSSHPublicKey: line) else { return nil }
        return sha256(ofBlob: blob)
    }

    /// The raw key blob out of the middle of an OpenSSH public key line.
    public static func blob(ofOpenSSHPublicKey line: String) -> Data? {
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        guard fields.count >= 2 else { return nil }
        return Data(base64Encoded: String(fields[1]))
    }

    private static func unpadded(_ base64: String) -> String {
        var text = base64
        while text.hasSuffix("=") { text.removeLast() }
        return text
    }
}

// MARK: - The keypair ServerOS owns

/// An Ed25519 keypair ServerOS owns.
///
/// The private half is 32 bytes of seed and nothing else: that is the whole key
/// for Ed25519, it is what the Keychain stores, and it is what
/// `Curve25519.Signing.PrivateKey(rawRepresentation:)` wants back.
public struct ServerOSKeyPair: Sendable, Equatable {

    /// 32 bytes. Keychain-bound: this value belongs in `ServerCredential` and
    /// nowhere else — not in a log, not in an error's `technical` field.
    public let privateKeySeed: Data

    /// `"ssh-ed25519 AAAA… serveros:<mac name>"` — the exact line appended to
    /// the server's `authorized_keys`.
    public let publicKeyAuthorizedKeysLine: String

    /// The comment field of the line above, after sanitising.
    public let comment: String

    /// The raw SSH public key blob, base64 of which is the middle field of the
    /// line above. Kept because the fingerprint is derived from it.
    public let publicKeyBlob: Data

    /// A fresh key. `comment` is what a person will see in `authorized_keys`,
    /// so it should say where the key came from: `"serveros:Orion's MacBook"`.
    public static func generate(comment: String) throws -> ServerOSKeyPair {
        let key = Curve25519.Signing.PrivateKey()
        return try from(seed: Data(key.rawRepresentation), comment: comment)
    }

    /// Rebuild a keypair from a seed the Keychain gave back.
    public static func from(seed: Data, comment: String) throws -> ServerOSKeyPair {
        guard seed.count == 32 else {
            throw ServerOSError.sshKeyUnusable(
                "An Ed25519 key is exactly 32 bytes; this one is \(seed.count).",
                technical: nil
            )
        }

        let key: Curve25519.Signing.PrivateKey
        do {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw ServerOSError.sshKeyUnusable(
                "The stored key material isn't a valid Ed25519 key.",
                technical: "\(error)"
            )
        }

        let rawPublicKey = Data(key.publicKey.rawRepresentation)
        let blob = SSHWire.ed25519PublicKeyBlob(rawPublicKey: rawPublicKey)
        let cleanComment = sanitised(comment: comment)
        let line = "\(SSHWire.ed25519Algorithm) \(blob.base64EncodedString()) \(cleanComment)"

        return ServerOSKeyPair(
            privateKeySeed: Data(key.rawRepresentation),
            publicKeyAuthorizedKeysLine: line,
            comment: cleanComment,
            publicKeyBlob: blob
        )
    }

    /// The form swift-nio-ssh authenticates with.
    public func nioPrivateKey() throws -> NIOSSHPrivateKey {
        do {
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeySeed)
            return NIOSSHPrivateKey(ed25519Key: key)
        } catch {
            throw ServerOSError.sshKeyUnusable(
                "The stored key material isn't a valid Ed25519 key.",
                technical: "\(error)"
            )
        }
    }

    /// `"SHA256:…"`, the string shown next to "Is this the right server?".
    public var sha256Fingerprint: String {
        SSHFingerprint.sha256(ofBlob: publicKeyBlob)
    }

    /// A comment is one field of one line in a file that is parsed by line. A
    /// newline in it would corrupt `authorized_keys`, and a missing one would
    /// produce a trailing space, so both are dealt with here rather than at
    /// each call site.
    static func sanitised(comment: String) -> String {
        let collapsed = comment
            .split(whereSeparator: { $0.isNewline || $0.isWhitespace })
            .joined(separator: " ")
        let trimmed = collapsed.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "serveros" : trimmed
    }
}
