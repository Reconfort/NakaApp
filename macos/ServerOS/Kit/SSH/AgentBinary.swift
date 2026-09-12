//  AgentBinary.swift
//  ServerOS
//
//  Which agent build belongs on which server, and where to find it.
//
//  ServerOS ships the Linux agent inside the app and pushes it down the SSH
//  connection it already holds, rather than asking the server to download it.
//  Two reasons, both of which showed up the first time this was pointed at a
//  real machine:
//
//    * A server worth managing often has no outbound internet. A setup flow
//      that assumes one fails in front of the user, at the last step, after
//      they have already handed over credentials.
//    * A download host is a promise. Until there is one, the honest thing is
//      to carry the binary rather than to point at a URL and hope.
//
//  `--base-url` still exists in the installer for organisations that mirror
//  the agent themselves. It is no longer the default, and it is no longer a
//  host that does not exist.

import Foundation

public enum AgentBinary {

    /// Architectures this build of ServerOS carries an agent for.
    ///
    /// Adding one means dropping `serveros-agent-linux-<arch>` into
    /// `Kit/SSH/Resources/` and adding the name here.
    public static let knownArchitectures = ["x86_64", "aarch64"]

    /// `uname -m` varies by distribution for the same hardware. Normalise to
    /// the names the agent is built and named under.
    public static func normalise(_ unameM: String) -> String {
        switch unameM.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "x86_64", "amd64", "x64":
            return "x86_64"
        case "aarch64", "arm64", "armv8l", "armv8b":
            return "aarch64"
        case let other:
            return other
        }
    }

    /// The resource name for one architecture.
    public static func resourceName(for architecture: String) -> String {
        "serveros-agent-linux-\(normalise(architecture))"
    }

    /// The bundled agent for this architecture, if this build carries one.
    public static func bundled(for architecture: String, in bundle: Bundle = .main) -> URL? {
        let name = resourceName(for: architecture)

        if let url = bundle.url(forResource: name, withExtension: nil) {
            return url
        }
        // Folder-synchronized groups can land resources in a subdirectory
        // rather than flat in Resources, depending on how Xcode copies them.
        if let url = bundle.url(forResource: name, withExtension: nil, subdirectory: "Resources") {
            return url
        }
        return nil
    }

    /// What this build can actually install, for an error message that tells
    /// the user something true rather than something generic.
    public static func bundledArchitectures(in bundle: Bundle = .main) -> [String] {
        knownArchitectures.filter { bundled(for: $0, in: bundle) != nil }
    }
}
