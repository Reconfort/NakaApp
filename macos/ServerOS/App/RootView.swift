//  RootView.swift
//  ServerOS
//
//  The window: sidebar on the left, one screen on the right.
//
//  `NavigationSplitView` with two columns rather than three. A third column
//  would be the obvious place for "the list of containers" — but every list in
//  this app wants a different layout (a table for processes, a grid for
//  containers, a tree for files), and forcing them all into a fixed-width
//  middle column would make every one of them worse.

import SwiftUI

public struct RootView: View {
    @Environment(AppModel.self) private var model
    @State private var navigation = NavigationModel()
    @State private var isShowingCommandPalette = false
    @State private var isShowingAddServer = false
    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    public init() {}

    public var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            Sidebar(
                navigation: navigation,
                onAddServer: { isShowingAddServer = true }
            )
            .navigationSplitViewColumnWidth(
                min: Layout.sidebarMinWidth,
                ideal: Layout.sidebarIdealWidth,
                max: Layout.sidebarMaxWidth
            )
        } detail: {
            detail
                .frame(minWidth: Layout.contentMinWidth)
                .background(Palette.background)
        }
        .navigationTitle(title)
        .navigationSubtitle(subtitle)
        .environment(navigation)
        .task {
            await model.load()
            model.connectAll()
        }
        .sheet(isPresented: $isShowingAddServer) {
            AddServerFlow { summary, credential in
                Task {
                    try? await model.add(summary, credential: credential)
                    navigation.enter(serverID: summary.id)
                }
            }
        }
        .overlay {
            if isShowingCommandPalette {
                CommandPalette(
                    isPresented: $isShowingCommandPalette,
                    items: model.paletteItems(currentServerID: navigation.route.serverID),
                    onSelect: handlePaletteSelection
                )
                .transition(.opacity.combined(with: .scale(scale: 0.98, anchor: .top)))
            }
        }
        .animation(Motion.panel, value: isShowingCommandPalette)
        .focusedSceneValue(\.navigation, navigation)
        .focusedSceneValue(\.commandPaletteTrigger) { isShowingCommandPalette = true }
        .focusedSceneValue(\.addServerTrigger) { isShowingAddServer = true }
    }

    // MARK: Detail

    @ViewBuilder
    private var detail: some View {
        switch navigation.route {
        case .overview:
            OverviewScreen(navigation: navigation, onAddServer: { isShowingAddServer = true })
        case .servers:
            ServersScreen(navigation: navigation, onAddServer: { isShowingAddServer = true })
        case .projects:
            FleetProjectsScreen(navigation: navigation)
        case .activity:
            FleetActivityScreen(navigation: navigation)
        case .settings:
            SettingsScreen()
        case .server(let id, let section):
            if let session = model.session(for: id) {
                ServerDetailScreen(session: session, section: section, navigation: navigation)
                    .id(id)
            } else {
                missingServer
            }
        }
    }

    private var missingServer: some View {
        EmptyState(
            systemImage: "questionmark.folder",
            title: "That server is no longer in ServerOS",
            message: "It may have been removed from another window.",
            actionTitle: "Show Servers",
            action: { navigation.go(to: .servers) }
        )
    }

    // MARK: Window title

    private var title: String {
        switch navigation.route {
        case .overview: return "Overview"
        case .servers: return "Servers"
        case .projects: return "Projects"
        case .activity: return "Activity"
        case .settings: return "Settings"
        case .server(let id, let section):
            let name = model.servers.first(where: { $0.id == id })?.name ?? "Server"
            return "\(name) — \(section.title)"
        }
    }

    private var subtitle: String {
        guard let id = navigation.route.serverID,
              let session = model.session(for: id) else { return "" }
        return session.phase.isReady ? session.health.state.label : session.phase.stepDescription(for: session.name)
    }

    // MARK: Palette

    private func handlePaletteSelection(_ item: PaletteItem) {
        isShowingCommandPalette = false
        let parts = item.id.split(separator: ":").map(String.init)

        switch parts.first {
        case "nav":
            if let section = FleetSection(rawValue: parts[1]) {
                navigation.go(to: section.route)
            }
        case "server":
            navigation.enter(serverID: parts[1])
        case "section":
            if parts.count >= 3, let section = ServerSection(rawValue: parts[2]) {
                navigation.enter(serverID: parts[1], section: section)
            }
        case "container":
            if parts.count >= 3 {
                navigation.selectedContainerID = parts[2]
                navigation.enter(serverID: parts[1], section: .docker)
            }
        case "service":
            if parts.count >= 3 {
                navigation.selectedServiceUnit = parts[2]
                navigation.enter(serverID: parts[1], section: .services)
            }
        case "action":
            handlePaletteAction(parts)
        default:
            break
        }
    }

    private func handlePaletteAction(_ parts: [String]) {
        guard parts.count >= 2 else { return }
        switch parts[1] {
        case "add-server":
            isShowingAddServer = true
        case "restart-container":
            guard parts.count >= 4, let session = model.session(for: parts[2]) else { return }
            let id = parts[3]
            Task { try? await session.api?.performContainerAction(.restart, id: id, graceSeconds: nil) }
            navigation.enter(serverID: parts[2], section: .docker)
        case "restart-service":
            guard parts.count >= 4, let session = model.session(for: parts[2]) else { return }
            let unit = parts[3]
            Task { try? await session.api?.performServiceAction(.restart, unit: unit) }
            navigation.enter(serverID: parts[2], section: .services)
        default:
            break
        }
    }
}

// MARK: - Focused values
//
// The menu bar lives in the `App` scene, outside any window, so commands reach
// the focused window through these rather than through a shared singleton.

public struct NavigationFocusKey: FocusedValueKey {
    public typealias Value = NavigationModel
}

public struct CommandPaletteFocusKey: FocusedValueKey {
    public typealias Value = () -> Void
}

public struct AddServerFocusKey: FocusedValueKey {
    public typealias Value = () -> Void
}

extension FocusedValues {
    public var navigation: NavigationModel? {
        get { self[NavigationFocusKey.self] }
        set { self[NavigationFocusKey.self] = newValue }
    }
    public var commandPaletteTrigger: (() -> Void)? {
        get { self[CommandPaletteFocusKey.self] }
        set { self[CommandPaletteFocusKey.self] = newValue }
    }
    public var addServerTrigger: (() -> Void)? {
        get { self[AddServerFocusKey.self] }
        set { self[AddServerFocusKey.self] = newValue }
    }
}
