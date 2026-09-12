//  ServerTunnel.swift
//  ServerOS
//
//  The bridge between "a server in the list" and "an SSH connection to it".
//
//  `ServerConnection` deliberately knows nothing about SSH — it takes an
//  `SSHTunneling` and asks it for a local port. This is the implementation that
//  does the real thing: read the credential out of the Keychain, stand up an
//  `SSHClient`, and forward a loopback port to the agent.
//
//  Keeping it here rather than inside `ServerConnection` means the whole
//  networking layer stays testable with a stub tunnel, and it means the SSH
//  dependency does not reach into every screen.

import Foundation

/// Opens an SSH connection on demand and forwards a port to the agent.
///
/// Lazy on purpose: an app with eight servers configured should not open eight
/// SSH connections at launch. The connection is made the first time a screen
/// actually needs that server.
public actor ServerTunnel: SSHTunneling {

    private let summary: ServerSummary
    private let credentials: CredentialStore
    private var client: SSHClient?
    private var localPort: Int?

    public init(summary: ServerSummary, credentials: CredentialStore = CredentialStore()) {
        self.summary = summary
        self.credentials = credentials
    }

    public func openTunnel(remotePort: Int) async throws -> Int {
        // Already forwarding: reuse it. Two screens asking at once must not
        // produce two SSH connections to the same box.
        if let localPort, client != nil {
            return localPort
        }

        guard let credential = try await credentials.load(serverID: summary.id) else {
            throw ServerOSError.noCredential
        }

        let authentication: SSHAuthentication
        if let seed = credential.sshPrivateKey {
            // The key ServerOS generated for itself during setup. Preferred:
            // it is per-Mac, revocable from the server's authorized_keys, and
            // means no password is stored anywhere.
            let pair = try ServerOSKeyPair.from(seed: seed, comment: "serveros")
            authentication = .privateKey(try pair.nioPrivateKey())
        } else if let password = credential.sshPassword {
            authentication = .password(password)
        } else {
            throw ServerOSError.noCredential
        }

        let client = SSHClient(
            host: summary.hostname,
            port: summary.sshPort,
            username: summary.sshUsername,
            authentication: authentication,
            pinnedHostKey: credential.hostKeyFingerprint
        )

        try await client.connect()
        let port = try await client.openTunnel(remotePort: remotePort)

        self.client = client
        self.localPort = port
        return port
    }

    public func close() async {
        if let client {
            await client.disconnect()
        }
        client = nil
        localPort = nil
    }

    /// The live SSH client, for the terminal — which needs a session channel
    /// rather than a forwarded port, and should share the one connection
    /// instead of opening a second.
    public func sshClient() -> SSHClient? { client }
}
