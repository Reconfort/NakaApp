//  ServerOSError.swift
//  ServerOS
//
//  Errors, shaped for the screen rather than for the debugger.
//
//  The product rule is that `ECONNREFUSED` is never the headline. Every failure
//  in this app resolves to three things:
//
//    headline   — what happened, in a sentence
//    causes     — what it is usually
//    technical  — the raw detail, behind a disclosure triangle
//
//  A failure that cannot answer all three is not finished being handled.

import Foundation

/// A failure the user might see.
public struct ServerOSError: Error, Equatable, Sendable, Identifiable {
    public let id: UUID
    /// Machine-readable, stable. Matches the agent's `error.code` when the
    /// failure came from the agent.
    public let code: String
    /// One sentence. Title case sentence, ends in a period.
    public let headline: String
    /// What this usually means, as bullet points. May be empty.
    public let causes: [String]
    /// Raw text for the "Technical details" disclosure. Never shown by default.
    public let technical: String?
    /// Whether retrying the same operation could plausibly work.
    public let isRetryable: Bool
    /// Whether the app should try to re-authenticate and retry once, silently.
    public let needsFreshCredential: Bool

    public init(
        code: String,
        headline: String,
        causes: [String] = [],
        technical: String? = nil,
        isRetryable: Bool = false,
        needsFreshCredential: Bool = false
    ) {
        self.id = UUID()
        self.code = code
        self.headline = headline
        self.causes = causes
        self.technical = technical
        self.isRetryable = isRetryable
        self.needsFreshCredential = needsFreshCredential
    }

    public static func == (lhs: ServerOSError, rhs: ServerOSError) -> Bool {
        lhs.code == rhs.code && lhs.headline == rhs.headline
    }
}

extension ServerOSError: LocalizedError {
    public var errorDescription: String? { headline }
    public var failureReason: String? { causes.first }
}

// MARK: - Construction from the wire

/// The error envelope every ServerOS component emits.
public struct WireError: Decodable, Sendable {
    public struct Body: Decodable, Sendable {
        public let code: String
        public let message: String
        public let detail: String?
    }
    public let error: Body
}

extension ServerOSError {

    /// Build from an agent or control-plane error response.
    ///
    /// The agent already writes user-facing sentences, so `message` is used as
    /// the headline verbatim. What this adds is the "what it usually is" list,
    /// which the agent has no business knowing — it depends on where the app is
    /// in its flow.
    public static func from(wire: WireError, status: Int) -> ServerOSError {
        let code = wire.error.code
        let message = wire.error.message
        let detail = wire.error.detail

        switch code {
        case "auth_expired":
            return ServerOSError(
                code: code,
                headline: "Your session with this server expired.",
                causes: ["ServerOS will get a new credential and try again."],
                technical: detail,
                isRetryable: true,
                needsFreshCredential: true
            )

        case "auth_missing", "auth_invalid", "auth_malformed", "auth_replayed", "auth_not_yet_valid":
            return ServerOSError(
                code: code,
                headline: "ServerOS isn't authorised on this server.",
                causes: [
                    "The stored credential no longer matches the agent",
                    "The agent was re-enrolled from another Mac",
                    "This Mac's clock is significantly wrong",
                ],
                technical: detail ?? message,
                isRetryable: false
            )

        case "auth_insufficient_scope":
            return ServerOSError(
                code: code,
                headline: message,
                causes: ["This connection was set up with limited access."],
                technical: detail,
                isRetryable: false
            )

        case "auth_rate_limited":
            return ServerOSError(
                code: code,
                headline: message,
                causes: ["The agent is rejecting requests after repeated failures."],
                technical: detail,
                isRetryable: true
            )

        case "agent_not_enrolled":
            return ServerOSError(
                code: code,
                headline: "This server's agent isn't set up yet.",
                causes: ["The agent is installed but has no identity. Re-run setup for this server."],
                technical: detail,
                isRetryable: false
            )

        case "subsystem_unavailable":
            return ServerOSError(
                code: code,
                headline: message,
                causes: [],
                technical: detail,
                isRetryable: false
            )

        case "not_found":
            return ServerOSError(
                code: code,
                headline: message,
                causes: ["It may have been removed since this screen last loaded."],
                technical: detail,
                isRetryable: true
            )

        case "denied":
            return ServerOSError(
                code: code,
                headline: message,
                causes: ["ServerOS refuses to touch this path to protect the server."],
                technical: detail,
                isRetryable: false
            )

        case "agent_busy":
            return ServerOSError(
                code: code,
                headline: "The agent is busy.",
                causes: ["Too many connections are open to this server right now."],
                technical: detail,
                isRetryable: true
            )

        default:
            return ServerOSError(
                code: code,
                headline: message,
                causes: [],
                technical: detail,
                // 5xx is worth retrying; 4xx means we asked for the wrong thing.
                isRetryable: status >= 500
            )
        }
    }

    /// Build from a transport failure, where there is no envelope to read.
    public static func transport(_ underlying: Error, serverName: String? = nil) -> ServerOSError {
        let ns = underlying as NSError
        let name = serverName.map { " \($0)" } ?? ""

        if ns.domain == NSURLErrorDomain {
            switch ns.code {
            case NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost:
                return ServerOSError(
                    code: "agent_unreachable",
                    headline: "ServerOS couldn't reach the agent on\(name).",
                    causes: [
                        "The agent may have stopped — check it with Reconnect",
                        "The SSH connection may have dropped",
                        "The server may be rebooting",
                    ],
                    technical: ns.localizedDescription,
                    isRetryable: true
                )
            case NSURLErrorTimedOut:
                return ServerOSError(
                    code: "agent_timeout",
                    headline: "The server\(name) didn't respond in time.",
                    causes: [
                        "The server may be under heavy load",
                        "The network between here and the server may be slow",
                    ],
                    technical: ns.localizedDescription,
                    isRetryable: true
                )
            case NSURLErrorCancelled:
                return ServerOSError(
                    code: "cancelled",
                    headline: "That request was cancelled.",
                    causes: [],
                    technical: nil,
                    isRetryable: true
                )
            default:
                break
            }
        }

        return ServerOSError(
            code: "transport_failed",
            headline: "ServerOS couldn't complete that request.",
            causes: ["The connection to\(name.isEmpty ? " the server" : name) failed."],
            technical: "\(ns.domain) \(ns.code): \(ns.localizedDescription)",
            isRetryable: true
        )
    }

    /// A response that arrived but could not be understood.
    ///
    /// Almost always an agent/app version mismatch, so the message says so
    /// instead of showing a decoding stack trace.
    public static func decoding(_ underlying: Error, endpoint: String) -> ServerOSError {
        ServerOSError(
            code: "unexpected_response",
            headline: "ServerOS didn't understand the server's reply.",
            causes: [
                "The agent on this server may be a different version to this app",
                "Update the agent from this server's settings",
            ],
            technical: "\(endpoint): \(underlying)",
            isRetryable: false
        )
    }

    // MARK: - Well-known app-side failures

    public static let noCredential = ServerOSError(
        code: "no_credential",
        headline: "ServerOS has no saved credential for this server.",
        causes: ["The Keychain item may have been removed. Set this server up again."],
        isRetryable: false
    )

    public static func sshFailed(_ reason: String, technical: String?) -> ServerOSError {
        ServerOSError(
            code: "ssh_failed",
            headline: "ServerOS couldn't open an SSH connection.",
            causes: [reason],
            technical: technical,
            isRetryable: true
        )
    }

    public static func hostKeyChanged(expected: String, actual: String) -> ServerOSError {
        ServerOSError(
            code: "host_key_changed",
            headline: "This server's identity has changed.",
            causes: [
                "The server may have been rebuilt or reinstalled",
                "Someone may be intercepting the connection",
                "ServerOS will not connect until you confirm the new key",
            ],
            technical: "Expected \(expected)\nReceived \(actual)",
            isRetryable: false
        )
    }
}

// MARK: - The SSH layer
//
// Appended by `Kit/SSH`. Everything here follows the rule at the top of the
// file: a headline a person can act on, the likely causes as fragments, and
// the shell output — which is what an engineer actually needs — behind
// "Technical details".

extension ServerOSError {

    /// The two ways out of an unreadable key file. Written once, because both
    /// the encrypted case and the RSA case need to say the same thing, and
    /// because half an instruction is worse than none.
    private static let bringYourOwnKeyAdvice = [
        "Let ServerOS create its own key for this server — it installs it for you",
        "Or make a copy of the key and run: ssh-keygen -t ed25519 -f <copy>",
    ]

    /// Key material that exists but cannot be used.
    public static func sshKeyUnusable(_ reason: String, technical: String?) -> ServerOSError {
        ServerOSError(
            code: "ssh_key_unusable",
            headline: "ServerOS couldn't use that SSH key.",
            causes: [reason],
            technical: technical,
            isRetryable: false
        )
    }

    /// A passphrase-protected private key.
    ///
    /// ServerOS does not decrypt these: the OpenSSH container uses bcrypt_pbkdf,
    /// which neither swift-crypto nor swift-nio-ssh implements, and shipping a
    /// KDF to handle a case with two good alternatives is not a trade worth
    /// making. So the message is an instruction, not an apology.
    public static let sshKeyEncrypted = ServerOSError(
        code: "ssh_key_encrypted",
        headline: "That key is protected by a passphrase.",
        causes: [
            "Let ServerOS create its own key for this server — it installs it for you",
            "Or copy the key and remove the passphrase from the copy: ssh-keygen -p -f <copy>",
        ],
        technical: nil,
        isRetryable: false
    )

    /// An RSA key. There is no RSA support anywhere in swift-nio-ssh — not
    /// disabled, not deprecated, absent — so this is a plain statement rather
    /// than something a setting could change.
    public static let sshKeyIsRSA = ServerOSError(
        code: "ssh_key_rsa_unsupported",
        headline: "ServerOS's SSH implementation doesn't support RSA keys.",
        causes: bringYourOwnKeyAdvice,
        technical: "swift-nio-ssh supports Ed25519 and ECDSA (P-256/384/521) only.",
        isRetryable: false
    )

    /// A key type ServerOS has no code path for.
    public static func sshKeyUnsupported(_ what: String) -> ServerOSError {
        ServerOSError(
            code: "ssh_key_unsupported",
            headline: "ServerOS can't read \(what).",
            causes: bringYourOwnKeyAdvice,
            technical: nil,
            isRetryable: false
        )
    }

    /// A key file that is the right type but the wrong bytes.
    public static func sshKeyMalformed(_ detail: String) -> ServerOSError {
        ServerOSError(
            code: "ssh_key_malformed",
            headline: "That key file is damaged.",
            causes: [
                "It may have been truncated when it was copied",
                "Check it with: ssh-keygen -y -f <key>",
            ],
            technical: detail,
            isRetryable: false
        )
    }

    /// An operation that needs a live SSH connection, without one.
    public static let sshNotConnected = ServerOSError(
        code: "ssh_not_connected",
        headline: "ServerOS isn't connected to this server.",
        causes: ["The connection may have dropped — reconnect and try again"],
        technical: nil,
        isRetryable: true
    )

    /// A remote command that ran and failed.
    ///
    /// The command itself is in `technical`, never in the headline: a user
    /// should not have to read shell to understand that something didn't work.
    public static func sshCommandFailed(command: String, exitStatus: Int32, stderr: String) -> ServerOSError {
        ServerOSError(
            code: "ssh_command_failed",
            headline: "A command on the server didn't complete.",
            causes: ["The server rejected it or it exited with an error"],
            technical: "$ \(command)\nexit \(exitStatus)\n\(stderr)",
            isRetryable: true
        )
    }

    public static func sshTimedOut(command: String, seconds: TimeInterval) -> ServerOSError {
        ServerOSError(
            code: "ssh_timeout",
            headline: "The server stopped responding.",
            causes: [
                "The server may be under heavy load",
                "The command may be waiting for input that never comes",
            ],
            technical: "$ \(command)\nno result after \(Int(seconds))s",
            isRetryable: true
        )
    }

    public static func sshTunnelFailed(_ reason: String, technical: String?) -> ServerOSError {
        ServerOSError(
            code: "ssh_tunnel_failed",
            headline: "ServerOS couldn't set up the secure tunnel to the agent.",
            causes: [reason],
            technical: technical,
            isRetryable: true
        )
    }

    // MARK: Setting a server up

    /// A step of the Add Server flow that failed. `step` is the step's own
    /// title, so the error says exactly where the flow stopped.
    public static func setupFailed(
        step: String,
        reason: String,
        causes: [String] = [],
        technical: String? = nil
    ) -> ServerOSError {
        ServerOSError(
            code: "setup_failed",
            headline: reason,
            causes: causes.isEmpty ? ["This happened while: \(step)"] : causes,
            technical: technical,
            isRetryable: true
        )
    }

    /// The server runs an architecture this build of ServerOS has no agent for.
    ///
    /// Worth its own case rather than a generic setup failure: nothing the user
    /// can do to the *server* fixes it, so an error that sends them to check
    /// disk space or networking wastes their time. The fix is to put a matching
    /// build in the app, and the message says so.
    public static func agentBuildUnavailable(architecture: String, available: [String]) -> ServerOSError {
        let arch = architecture.isEmpty ? "this server's architecture" : architecture
        var causes = [
            "ServerOS installs the agent by copying it to the server, and this "
            + "build doesn't include one for \(arch)."
        ]
        if available.isEmpty {
            causes.append("This build includes no agent at all — it was assembled without one.")
        } else {
            causes.append("It includes: \(available.joined(separator: ", ")).")
        }
        causes.append(
            "To add one: on any \(arch) Linux machine run `cd agent && cargo build "
            + "--release`, copy the result to macos/ServerOS/Kit/SSH/Resources/"
            + "serveros-agent-linux-\(arch), and rebuild ServerOS."
        )
        return ServerOSError(
            code: "agent_build_unavailable",
            headline: "ServerOS doesn't have an agent built for this server.",
            causes: causes,
            technical: "uname -m reported \(architecture.isEmpty ? "(nothing)" : architecture); "
                + "bundled: \(available.isEmpty ? "none" : available.joined(separator: ", "))",
            isRetryable: false
        )
    }

    public static func serverIsNotLinux(_ systemName: String) -> ServerOSError {
        ServerOSError(
            code: "not_linux",
            headline: "ServerOS manages Linux servers, and this one reports “\(systemName)”.",
            causes: [
                "macOS, BSD and Windows hosts aren't supported",
                "If this is a Linux container, check you connected to the host",
            ],
            technical: "uname -s returned \(systemName)",
            isRetryable: false
        )
    }

    public static func enrollmentBundleNotFound(technical: String?) -> ServerOSError {
        ServerOSError(
            code: "enrollment_not_found",
            headline: "The agent didn't hand back an enrollment key.",
            causes: [
                "The agent may have failed to write /etc/serveros/agent.key",
                "The account may not have permission to run it as root",
            ],
            technical: technical,
            isRetryable: true
        )
    }

    public static let sudoUnavailable = ServerOSError(
        code: "sudo_unavailable",
        headline: "Setting up the agent needs administrator access on the server.",
        causes: [
            "This account isn't root and sudo isn't installed",
            "Connect as root, or as a user who can run sudo",
        ],
        technical: nil,
        isRetryable: false
    )

    /// Passwordless sudo specifically.
    ///
    /// ServerOS will not pipe a password into `sudo -S`: the command line of a
    /// running process is readable by every user on the machine, and a setup
    /// flow is not worth putting a root password there.
    public static let sudoNeedsPassword = ServerOSError(
        code: "sudo_needs_password",
        headline: "This account needs a password for sudo, which ServerOS can't provide.",
        causes: [
            "Connect as root instead",
            "Or allow this account to run sudo without a password on this server",
        ],
        technical: "sudo -n true failed",
        isRetryable: false
    )
}
