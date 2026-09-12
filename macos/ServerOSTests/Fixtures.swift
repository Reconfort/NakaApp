//  Fixtures.swift
//  ServerOSTests
//
//  Finding the captured agent responses.
//
//  The fixtures in `macos/fixtures/` are real JSON from a running agent, and
//  the decoding tests are the only thing standing between an agent field
//  rename and a blank row on a user's screen months later. So loading them must
//  never be the reason a test is skipped.
//
//  Two lookup paths, in order:
//
//    1. The test bundle, for when the fixtures have been added to the test
//       target's resources — the normal case, and the only one that works on a
//       CI machine with no checkout layout.
//    2. The repository, resolved from `#filePath` at compile time. This makes
//       the tests work the first time someone opens the project, before anyone
//       has remembered to tick "Copy Bundle Resources".

import Foundation
import XCTest

/// Anchors `Bundle(for:)` to this test bundle.
private final class FixtureAnchor {}

enum FixtureError: Error, CustomStringConvertible {
    case missing(String, searched: [String])

    var description: String {
        switch self {
        case .missing(let name, let searched):
            return "Fixture \(name) not found. Looked in:\n  " + searched.joined(separator: "\n  ")
        }
    }
}

enum Fixtures {

    /// Every fixture file, so a test can assert that none is left undecoded.
    static let allNames: [String] = [
        "activity.json",
        "capabilities.json",
        "databases.json",
        "docker_containers.json",
        "docker_images.json",
        "docker_info.json",
        "docker_inspect.json",
        "docker_networks.json",
        "docker_volumes.json",
        "error_denied.json",
        "error_notfound.json",
        "files_list.json",
        "files_read.json",
        "files_stat.json",
        "groups.json",
        "health.json",
        "metrics.json",
        "pg_connections.json",
        "pg_databases.json",
        "pg_overview.json",
        "pg_roles.json",
        "processes.json",
        "projects.json",
        "services.json",
        "system.json",
        "users.json",
    ]

    /// Where the repository's fixtures live, worked out from this file's path.
    static var repositoryDirectory: URL {
        URL(fileURLWithPath: #filePath)          // …/macos/ServerOSTests/Fixtures.swift
            .deletingLastPathComponent()          // …/macos/ServerOSTests
            .deletingLastPathComponent()          // …/macos
            .appendingPathComponent("fixtures")   // …/macos/fixtures
    }

    static func url(_ name: String) throws -> URL {
        let base = (name as NSString).deletingPathExtension
        let bundle = Bundle(for: FixtureAnchor.self)
        var searched: [String] = []

        if let found = bundle.url(forResource: base, withExtension: "json") {
            return found
        }
        searched.append("\(bundle.bundlePath)/\(base).json")

        if let found = bundle.url(forResource: base, withExtension: "json", subdirectory: "fixtures") {
            return found
        }
        searched.append("\(bundle.bundlePath)/fixtures/\(base).json")

        let onDisk = repositoryDirectory.appendingPathComponent("\(base).json")
        if FileManager.default.fileExists(atPath: onDisk.path) {
            return onDisk
        }
        searched.append(onDisk.path)

        throw FixtureError.missing(name, searched: searched)
    }

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: try url(name))
    }

    /// Decode a fixture into a model.
    ///
    /// Failures carry the fixture name, because "keyNotFound(size_bytes)" on its
    /// own does not say which endpoint drifted.
    static func decode<T: Decodable>(_ type: T.Type, from name: String) throws -> T {
        let raw = try data(name)
        do {
            return try JSONDecoder().decode(type, from: raw)
        } catch {
            XCTFail("\(name) did not decode as \(type): \(error)")
            throw error
        }
    }
}
