//  OpenSSHKeyParser.swift
//  ServerOS
//
//  Reading the key the user already has.
//
//  Most people who own a Linux server already have `~/.ssh/id_ed25519`, and
//  telling them "ServerOS can't read your key, make a new one" for no reason
//  would be a bad first impression. So ServerOS reads it.
//
//  Neither swift-nio-ssh nor swift-crypto contains a parser for the modern
//  OpenSSH private key container — the `-----BEGIN OPENSSH PRIVATE KEY-----`
//  file that `ssh-keygen` has written by default since 7.8. swift-crypto's PEM
//  initialisers only understand PKCS#8 and SEC1. So this file implements the
//  container, which is a small, stable, well-documented format:
//
//      "openssh-key-v1\0"
//      string   ciphername            "none" when there is no passphrase
//      string   kdfname               "none"
//      string   kdfoptions            empty when kdfname is "none"
//      uint32   number of keys        always 1 in practice
//      string   public key blob
//      string   private section       (encrypted when ciphername != "none")
//
//  and inside the private section:
//
//      uint32   checkint              two copies of the same random number,
//      uint32   checkint              which is how a wrong passphrase is caught
//      string   keytype
//      ...      key material, per type
//      string   comment
//      bytes    padding               1, 2, 3, … up to the cipher block size
//
//  What is deliberately NOT implemented is decryption. A passphrase-protected
//  key needs bcrypt_pbkdf, which means shipping a KDF implementation to handle
//  a case where the user has two better options — and a wrong answer there is
//  worse than no answer. So an encrypted key gets a clear instruction instead
//  of a half-hearted attempt.

import Foundation
import Crypto
import NIOSSH

/// A private key ServerOS was able to read.
///
/// Only the two types that are both common in the wild and supported by
/// swift-nio-ssh. There is no RSA case because there is no RSA support to
/// have one for.
public enum ParsedPrivateKey: Sendable, Equatable {
    /// The 32-byte Ed25519 seed.
    case ed25519(Data)
    /// The 32-byte P-256 private scalar.
    case p256(Data)

    /// The form swift-nio-ssh authenticates with.
    public func nioPrivateKey() throws -> NIOSSHPrivateKey {
        switch self {
        case .ed25519(let seed):
            do {
                return NIOSSHPrivateKey(ed25519Key: try Curve25519.Signing.PrivateKey(rawRepresentation: seed))
            } catch {
                throw ServerOSError.sshKeyUnusable(
                    "The Ed25519 key material in that file isn't valid.",
                    technical: "\(error)"
                )
            }
        case .p256(let scalar):
            do {
                return NIOSSHPrivateKey(p256Key: try P256.Signing.PrivateKey(rawRepresentation: scalar))
            } catch {
                throw ServerOSError.sshKeyUnusable(
                    "The ECDSA P-256 key material in that file isn't valid.",
                    technical: "\(error)"
                )
            }
        }
    }

    /// The matching `authorized_keys` line, so the Add Server screen can show
    /// the user which key it is about to use.
    public func publicKeyAuthorizedKeysLine(comment: String) throws -> String {
        let cleanComment = ServerOSKeyPair.sanitised(comment: comment)
        switch self {
        case .ed25519(let seed):
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let blob = SSHWire.ed25519PublicKeyBlob(rawPublicKey: Data(key.publicKey.rawRepresentation))
            return "\(SSHWire.ed25519Algorithm) \(blob.base64EncodedString()) \(cleanComment)"
        case .p256(let scalar):
            let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
            // ecdsa blobs carry the curve name as well as the algorithm name,
            // and the point in uncompressed x9.63 form.
            let blob = SSHWire.string(SSHWire.p256Algorithm)
                + SSHWire.string("nistp256")
                + SSHWire.string(Data(key.publicKey.x963Representation))
            return "\(SSHWire.p256Algorithm) \(blob.base64EncodedString()) \(cleanComment)"
        }
    }
}

/// Turns a key file on disk into something swift-nio-ssh can use.
public enum OpenSSHKeyParser {

    // MARK: - Entry points

    /// Parse a key file's contents.
    public static func parse(_ text: String) throws -> ParsedPrivateKey {
        guard let block = PEMBlock.first(in: text) else {
            throw ServerOSError.sshKeyUnusable(
                "That file doesn't look like an SSH private key.",
                technical: "no PEM armour found"
            )
        }

        // A legacy PEM header is how pre-7.8 `ssh-keygen` marked an encrypted
        // key. It is worth catching separately: the body is unreadable for a
        // completely different reason than an openssh-key-v1 container's is.
        if block.headers.contains(where: { $0.lowercased().hasPrefix("proc-type:") && $0.contains("ENCRYPTED") }) {
            throw ServerOSError.sshKeyEncrypted
        }

        switch block.label {
        case "OPENSSH PRIVATE KEY":
            return try parseOpenSSHContainer(block.body)

        case "RSA PRIVATE KEY":
            throw ServerOSError.sshKeyIsRSA

        case "EC PRIVATE KEY":
            return try parseSEC1P256(pem: block.armoured)

        case "PRIVATE KEY":
            // PKCS#8. swift-crypto's `Crypto` module has no Ed25519 PEM
            // initialiser (that lives in the separate `_CryptoExtras` product,
            // which this target deliberately does not depend on), but an
            // Ed25519 PKCS#8 key is 48 bytes with a fixed 16-byte prefix, so
            // it is cheaper to recognise it than to depend on a product for it.
            if let seed = ed25519SeedFromPKCS8(block.body) {
                return .ed25519(seed)
            }
            return try parseSEC1P256(pem: block.armoured)

        case "DSA PRIVATE KEY":
            throw ServerOSError.sshKeyUnsupported("a DSA key")

        case "ENCRYPTED PRIVATE KEY":
            throw ServerOSError.sshKeyEncrypted

        default:
            throw ServerOSError.sshKeyUnsupported("a “\(block.label)” file")
        }
    }

    /// Parse a key file from disk.
    public static func parse(contentsOf url: URL) throws -> ParsedPrivateKey {
        let text: String
        do {
            text = try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw ServerOSError.sshKeyUnusable(
                "ServerOS couldn't read \(url.lastPathComponent).",
                technical: "\(error)"
            )
        }
        return try parse(text)
    }

    // MARK: - openssh-key-v1

    static let openSSHMagic = Data("openssh-key-v1\u{0}".utf8)

    static func parseOpenSSHContainer(_ body: Data) throws -> ParsedPrivateKey {
        var reader = SSHWireReader(body)

        let magic: Data
        do {
            magic = try reader.readBytes(openSSHMagic.count)
        } catch {
            throw malformed("the file is too short to be an OpenSSH key")
        }
        guard magic == openSSHMagic else {
            throw malformed("missing the openssh-key-v1 marker")
        }

        // The cipher name is checked before anything else is read: if the key
        // has a passphrase, every field after this point is ciphertext, and
        // "this key is encrypted" is a far more useful thing to say than
        // "this key is damaged".
        let cipherName: String
        let kdfName: String
        do {
            cipherName = try reader.readText()
            kdfName = try reader.readText()
        } catch {
            throw malformed("the key header is truncated")
        }
        guard cipherName == "none", kdfName == "none" else {
            throw ServerOSError.sshKeyEncrypted
        }

        let keyCount: UInt32
        let privateSection: Data
        do {
            _ = try reader.readString()          // kdfoptions: salt and rounds
            keyCount = try reader.readUInt32()
            _ = try reader.readString()          // the public key blob; the
                                                 // private section carries its
                                                 // own copy, checked below
            privateSection = try reader.readString()
        } catch {
            throw malformed("the key header is truncated")
        }

        guard keyCount == 1 else {
            throw ServerOSError.sshKeyUnsupported("a file holding \(keyCount) keys")
        }

        var priv = SSHWireReader(privateSection)
        let check1: UInt32
        let check2: UInt32
        let keyType: String
        do {
            check1 = try priv.readUInt32()
            check2 = try priv.readUInt32()
            keyType = try priv.readText()
        } catch {
            throw malformed("the private section is truncated")
        }
        guard check1 == check2 else {
            // With ciphername "none" there is no passphrase to have got wrong,
            // so this only ever means a damaged file.
            throw malformed("the private section's check bytes don't match")
        }

        switch keyType {
        case SSHWire.ed25519Algorithm:
            do {
                let publicKey = try priv.readString()
                let privateKey = try priv.readString()
                // OpenSSH stores seed ‖ public key, 64 bytes, for Ed25519.
                guard privateKey.count == 64, publicKey.count == 32 else {
                    throw malformed("unexpected Ed25519 key sizes")
                }
                let seed = Data(privateKey.prefix(32))
                let trailing = Data(privateKey.suffix(32))
                guard trailing == publicKey else {
                    throw malformed("the Ed25519 private key doesn't match its public key")
                }
                return .ed25519(seed)
            } catch let error as ServerOSError {
                throw error
            } catch {
                throw malformed("the Ed25519 key material is truncated")
            }

        case SSHWire.p256Algorithm:
            do {
                let curve = try priv.readText()
                guard curve == "nistp256" else {
                    throw ServerOSError.sshKeyUnsupported("an ECDSA key on curve “\(curve)”")
                }
                _ = try priv.readString()    // the public point; CryptoKit derives it
                let scalar = try priv.readFixedWidthBignum(width: 32)
                return .p256(scalar)
            } catch let error as ServerOSError {
                throw error
            } catch {
                throw malformed("the ECDSA key material is truncated")
            }

        case "ssh-rsa":
            throw ServerOSError.sshKeyIsRSA

        case "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            throw ServerOSError.sshKeyUnsupported("an \(keyType) key")

        case "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
            throw ServerOSError.sshKeyUnsupported("a hardware security key (\(keyType))")

        default:
            throw ServerOSError.sshKeyUnsupported("an “\(keyType)” key")
        }
    }

    // MARK: - SEC1 / PKCS#8

    static func parseSEC1P256(pem: String) throws -> ParsedPrivateKey {
        do {
            let key = try P256.Signing.PrivateKey(pemRepresentation: pem)
            return .p256(Data(key.rawRepresentation))
        } catch {
            // The same armour is used for P-384 and P-521, and for keys this
            // app has no support for. Say so rather than showing the ASN.1
            // failure, which explains nothing to anybody.
            throw ServerOSError.sshKeyUnsupported(
                "that key — ServerOS reads Ed25519 and ECDSA P-256 keys"
            )
        }
    }

    /// RFC 8410 §7: a v1 PKCS#8 Ed25519 private key is exactly 48 bytes, the
    /// first 16 of which are constant — SEQUENCE, version 0, the id-Ed25519
    /// OID (1.3.101.112), then an OCTET STRING wrapping an OCTET STRING of the
    /// 32-byte seed.
    static func ed25519SeedFromPKCS8(_ der: Data) -> Data? {
        let prefix: [UInt8] = [
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ]
        let bytes = Array(der)
        guard bytes.count == prefix.count + 32 else { return nil }
        guard Array(bytes.prefix(prefix.count)) == prefix else { return nil }
        return Data(bytes.suffix(32))
    }

    // MARK: - Helpers

    static func malformed(_ detail: String) -> ServerOSError {
        ServerOSError.sshKeyMalformed(detail)
    }
}

// MARK: - PEM armour

/// One `-----BEGIN X-----` … `-----END X-----` block.
struct PEMBlock {
    /// The label between the dashes, e.g. `OPENSSH PRIVATE KEY`.
    let label: String
    /// Header lines (`Proc-Type: 4,ENCRYPTED`), which only legacy keys have.
    let headers: [String]
    /// The decoded body.
    let body: Data
    /// The block as it appeared, which is what swift-crypto's PEM
    /// initialisers want to be handed.
    let armoured: String

    static func first(in text: String) -> PEMBlock? {
        let lines = text.split(whereSeparator: { $0.isNewline }).map { String($0).trimmingCharacters(in: .whitespaces) }

        guard let beginIndex = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN ") && $0.hasSuffix("-----") }) else {
            return nil
        }
        let beginLine = lines[beginIndex]
        let label = String(beginLine.dropFirst("-----BEGIN ".count).dropLast("-----".count))

        guard let endIndex = lines[beginIndex...].firstIndex(where: { $0.hasPrefix("-----END ") }) else {
            return nil
        }

        var headers: [String] = []
        var base64 = ""
        var inHeaders = true
        for line in lines[(beginIndex + 1)..<endIndex] {
            if inHeaders, line.contains(":") {
                headers.append(line)
                continue
            }
            if line.isEmpty {
                inHeaders = false
                continue
            }
            inHeaders = false
            base64 += line
        }

        guard let body = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]) else {
            return nil
        }

        let armoured = lines[beginIndex...endIndex].joined(separator: "\n") + "\n"
        return PEMBlock(label: label, headers: headers, body: body, armoured: armoured)
    }
}
