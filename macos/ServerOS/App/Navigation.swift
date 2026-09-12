//  Navigation.swift
//  ServerOS
//
//  The application's map.
//
//  There are two modes, and the distinction is the single most important
//  structural decision in the product:
//
//    Fleet mode   — no server chosen. Overview, Servers, Projects, Activity.
//                   Questions about the estate as a whole.
//    Server mode  — a server chosen. Its own Overview, Docker, Databases,
//                   Services, Users, Files, Processes, Logs, Terminal.
//                   You have *entered* that server.
//
//  The alternative — one flat global list of every resource on every server —
//  was rejected deliberately. It forces the user to carry "which server is this
//  row on?" in their head on every screen, and it stops scaling the moment
//  someone has four servers running the same three containers.

import SwiftUI

// MARK: - Routes

/// Where the window is.
public enum AppRoute: Hashable, Identifiable {
    case overview
    case servers
    case projects
    case activity
    case settings
    /// Inside one server.
    case server(id: String, section: ServerSection)

    public var id: String {
        switch self {
        case .overview: return "overview"
        case .servers: return "servers"
        case .projects: return "projects"
        case .activity: return "activity"
        case .settings: return "settings"
        case .server(let id, let section): return "server:\(id):\(section.rawValue)"
        }
    }

    /// The server this route belongs to, if any.
    public var serverID: String? {
        if case .server(let id, _) = self { return id }
        return nil
    }

    public var section: ServerSection? {
        if case .server(_, let section) = self { return section }
        return nil
    }

    /// Same server, different section.
    public func switching(to section: ServerSection) -> AppRoute {
        guard case .server(let id, _) = self else { return self }
        return .server(id: id, section: section)
    }
}

/// The sections available inside one server.
///
/// Ordered as they appear in the sidebar: the things people look at most, first.
public enum ServerSection: String, CaseIterable, Hashable, Sendable {
    case overview
    case projects
    case docker
    case databases
    case services
    case users
    case files
    case processes
    case logs
    case terminal

    public var title: String {
        switch self {
        case .overview: return "Overview"
        case .projects: return "Projects"
        case .docker: return "Docker"
        case .databases: return "Databases"
        case .services: return "Services"
        case .users: return "Users"
        case .files: return "Files"
        case .processes: return "Processes"
        case .logs: return "Logs"
        case .terminal: return "Terminal"
        }
    }

    public var symbol: String {
        switch self {
        case .overview: return "gauge.medium"
        case .projects: return "square.stack.3d.up"
        case .docker: return "shippingbox"
        case .databases: return "cylinder.split.1x2"
        case .services: return "gearshape.2"
        case .users: return "person.2"
        case .files: return "folder"
        case .processes: return "list.bullet.rectangle"
        case .logs: return "text.alignleft"
        case .terminal: return "terminal"
        }
    }

    /// Whether this server can offer the section at all.
    ///
    /// A section the server cannot do is hidden rather than shown-and-broken.
    /// Overview, Files, Processes, Logs and Terminal are always available,
    /// because every Linux box has them.
    public func isAvailable(given capabilities: AgentCapabilities) -> Bool {
        switch self {
        case .overview, .terminal: return true
        case .projects, .docker: return capabilities.docker
        case .databases: return capabilities.postgres
        case .services: return capabilities.services
        case .users: return capabilities.users
        case .files: return capabilities.files
        case .processes: return capabilities.processes
        case .logs: return capabilities.logs
        }
    }

    /// Sections that sit apart at the bottom of the sidebar, because they are
    /// escape hatches rather than destinations.
    public var isUtility: Bool { self == .terminal }

    /// ⌘1…⌘9, assigned in sidebar order. Terminal gets ⌘0.
    public var keyboardShortcut: Character? {
        switch self {
        case .overview: return "1"
        case .projects: return "2"
        case .docker: return "3"
        case .databases: return "4"
        case .services: return "5"
        case .users: return "6"
        case .files: return "7"
        case .processes: return "8"
        case .logs: return "9"
        case .terminal: return "0"
        }
    }
}

/// The fleet-level destinations.
public enum FleetSection: String, CaseIterable, Hashable {
    case overview, servers, projects, activity

    public var title: String {
        switch self {
        case .overview: return "Overview"
        case .servers: return "Servers"
        case .projects: return "Projects"
        case .activity: return "Activity"
        }
    }

    public var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .servers: return "server.rack"
        case .projects: return "square.stack.3d.up"
        case .activity: return "clock.arrow.circlepath"
        }
    }

    public var route: AppRoute {
        switch self {
        case .overview: return .overview
        case .servers: return .servers
        case .projects: return .projects
        case .activity: return .activity
        }
    }

    public var keyboardShortcut: Character {
        switch self {
        case .overview: return "1"
        case .servers: return "2"
        case .projects: return "3"
        case .activity: return "4"
        }
    }
}

// MARK: - Navigation state

/// The window's navigation, including its back stack.
///
/// Kept separate from `AppModel` so a second window can have its own place in
/// the app while sharing the same servers and connections.
@MainActor
@Observable
public final class NavigationModel {
    public private(set) var route: AppRoute = .overview
    /// Where "back" goes. Bounded, because an unbounded history in a
    /// long-running window is just a leak.
    private var history: [AppRoute] = []
    private let historyLimit = 32

    /// Set when the user drills into a specific resource, so the section can
    /// restore it. Keyed by section so switching away and back is lossless.
    public var selectedContainerID: String?
    public var selectedServiceUnit: String?
    public var selectedUserName: String?
    public var selectedProjectName: String?
    public var currentFilePath: String = "/"

    public init() {}

    public func go(to newRoute: AppRoute) {
        guard newRoute != route else { return }
        history.append(route)
        if history.count > historyLimit { history.removeFirst() }
        route = newRoute
    }

    /// Enter a server at its Overview.
    public func enter(serverID: String, section: ServerSection = .overview) {
        go(to: .server(id: serverID, section: section))
    }

    /// Switch section without leaving the server.
    public func select(section: ServerSection) {
        guard let id = route.serverID else { return }
        go(to: .server(id: id, section: section))
    }

    public var canGoBack: Bool { !history.isEmpty }

    public func goBack() {
        guard let previous = history.popLast() else { return }
        route = previous
    }

    /// Leave the current server and return to the server list.
    public func leaveServer() {
        go(to: .servers)
    }

    /// Drop any route that points at a server that no longer exists.
    public func forgetServer(id: String) {
        history.removeAll { $0.serverID == id }
        if route.serverID == id {
            route = .servers
        }
    }
}

// MARK: - Command palette targets

/// Anything ⌘K can find. Navigation and actions share one list, because from
/// the user's side "go to Docker" and "restart nginx" are the same gesture.
public struct PaletteItem: Identifiable, Hashable {
    public enum Kind: String {
        case navigation, server, container, service, project, action, file

        var symbol: String {
            switch self {
            case .navigation: return "arrow.right"
            case .server: return "server.rack"
            case .container: return "shippingbox"
            case .service: return "gearshape.2"
            case .project: return "square.stack.3d.up"
            case .action: return "bolt"
            case .file: return "doc"
            }
        }

        var label: String {
            switch self {
            case .navigation: return "Go to"
            case .server: return "Server"
            case .container: return "Container"
            case .service: return "Service"
            case .project: return "Project"
            case .action: return "Action"
            case .file: return "File"
            }
        }
    }

    public let id: String
    public let kind: Kind
    public let title: String
    public let subtitle: String?
    /// Extra words that should match but are not displayed — "container" for a
    /// Docker row, the server's name for a nested resource.
    public let searchTerms: [String]

    public init(id: String, kind: Kind, title: String, subtitle: String? = nil, searchTerms: [String] = []) {
        self.id = id
        self.kind = kind
        self.title = title
        self.subtitle = subtitle
        self.searchTerms = searchTerms
    }

    public static func == (lhs: PaletteItem, rhs: PaletteItem) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

/// Subsequence matching with a score, the way every good palette works.
///
/// Typing "dkr" should find "Docker", and "rsng" should find "Restart nginx".
/// Contiguous runs and word-boundary hits score higher, so the obvious answer
/// comes first.
public enum FuzzyMatch {

    /// Returns nil when there is no match at all.
    public static func score(_ candidate: String, query: String) -> Int? {
        guard !query.isEmpty else { return 0 }
        let haystack = Array(candidate.lowercased())
        let needle = Array(query.lowercased())
        guard needle.count <= haystack.count else { return nil }

        var score = 0
        var haystackIndex = 0
        var previousMatchIndex = -1

        for character in needle {
            var found = false
            while haystackIndex < haystack.count {
                if haystack[haystackIndex] == character {
                    // Adjacent to the previous match: this is a real substring.
                    if previousMatchIndex == haystackIndex - 1 { score += 8 }
                    // At the start of a word: "dc" matching "docker compose".
                    if haystackIndex == 0 { score += 12 }
                    else if haystack[haystackIndex - 1] == " "
                            || haystack[haystackIndex - 1] == "-"
                            || haystack[haystackIndex - 1] == "_"
                            || haystack[haystackIndex - 1] == "/" { score += 10 }
                    score += 1
                    previousMatchIndex = haystackIndex
                    haystackIndex += 1
                    found = true
                    break
                }
                haystackIndex += 1
            }
            if !found { return nil }
        }

        // Prefer shorter candidates: "Docker" should beat "Docker Networks".
        score -= max(0, (haystack.count - needle.count) / 8)
        return score
    }

    /// Rank items, best first. An empty query returns everything in order.
    public static func rank(_ items: [PaletteItem], query: String) -> [PaletteItem] {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return items }

        return items.compactMap { item -> (PaletteItem, Int)? in
            var best: Int?
            for candidate in [item.title] + (item.subtitle.map { [$0] } ?? []) + item.searchTerms {
                if let s = score(candidate, query: trimmed) {
                    // The title is what the user is looking at, so weight it.
                    let weighted = candidate == item.title ? s + 20 : s
                    best = max(best ?? Int.min, weighted)
                }
            }
            return best.map { (item, $0) }
        }
        .sorted { $0.1 > $1.1 }
        .map(\.0)
    }
}
