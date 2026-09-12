//  Sidebar.swift
//  ServerOS
//
//  The navigation backbone.
//
//  It has two faces, and switching between them is the app's main gesture:
//
//    fleet   — the estate: Overview, Servers, Projects, Activity, and the list
//              of servers with their health showing.
//    server  — inside one server: a back affordance, the server's identity and
//              state, then its own sections.
//
//  Sections a server cannot offer are simply absent. A Docker row that leads to
//  "Docker isn't installed" is worse than no Docker row.

import SwiftUI

public struct Sidebar: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let navigation: NavigationModel
    let onAddServer: () -> Void

    public init(navigation: NavigationModel, onAddServer: @escaping () -> Void) {
        self.navigation = navigation
        self.onAddServer = onAddServer
    }

    public var body: some View {
        VStack(spacing: 0) {
            if let serverID = navigation.route.serverID, let session = model.session(for: serverID) {
                serverSidebar(session)
                    .transition(.move(edge: .trailing).combined(with: .opacity))
            } else {
                fleetSidebar
                    .transition(.move(edge: .leading).combined(with: .opacity))
            }

            Spacer(minLength: 0)
            Divider().overlay(Palette.divider)
            footer
        }
        .animation(Motion.honouring(reduceMotion, Motion.appear), value: navigation.route.serverID)
        .background(.regularMaterial)
    }

    // MARK: Fleet

    private var fleetSidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.card) {
                VStack(spacing: 1) {
                    ForEach(FleetSection.allCases, id: \.self) { section in
                        SidebarRow(
                            title: section.title,
                            symbol: section.symbol,
                            isSelected: navigation.route == section.route
                        ) {
                            navigation.go(to: section.route)
                        }
                    }
                }

                if !model.servers.isEmpty {
                    VStack(alignment: .leading, spacing: Spacing.tight) {
                        Text("Servers")
                            .font(Typography.metadata.weight(.semibold))
                            .foregroundStyle(Palette.textMuted)
                            .textCase(.uppercase)
                            .tracking(0.5)
                            .padding(.horizontal, Spacing.element)
                            .accessibilityAddTraits(.isHeader)

                        VStack(spacing: 1) {
                            ForEach(model.servers) { summary in
                                ServerSidebarRow(
                                    summary: summary,
                                    health: model.sessions[summary.id]?.health ?? .unknown,
                                    isSelected: navigation.route.serverID == summary.id
                                ) {
                                    navigation.enter(serverID: summary.id)
                                }
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, Spacing.element)
            .padding(.top, Spacing.element)
        }
    }

    // MARK: Server

    private func serverSidebar(_ session: ServerSession) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.card) {
                Button {
                    navigation.leaveServer()
                } label: {
                    HStack(spacing: Spacing.tight) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 10, weight: .semibold))
                        Text("Servers").font(Typography.secondary)
                    }
                    .foregroundStyle(Palette.textSecondary)
                    .padding(.vertical, Spacing.tight)
                    .padding(.horizontal, Spacing.element)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Back to all servers")

                VStack(alignment: .leading, spacing: Spacing.snug) {
                    Text(session.name)
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(2)
                    HealthBadge(session.health.state, compact: true)
                    if session.isDemo {
                        Chip("Demo", tint: Palette.informational, systemImage: "wand.and.stars")
                    }
                }
                .padding(.horizontal, Spacing.element)

                VStack(spacing: 1) {
                    ForEach(availableSections(for: session), id: \.self) { section in
                        SidebarRow(
                            title: section.title,
                            symbol: section.symbol,
                            isSelected: navigation.route.section == section,
                            badge: badge(for: section, session: session)
                        ) {
                            navigation.select(section: section)
                        }
                    }
                }

                let utilities = ServerSection.allCases.filter {
                    $0.isUtility && $0.isAvailable(given: session.capabilities)
                }
                if !utilities.isEmpty {
                    Divider().overlay(Palette.divider).padding(.horizontal, Spacing.element)
                    VStack(spacing: 1) {
                        ForEach(utilities, id: \.self) { section in
                            SidebarRow(
                                title: section.title,
                                symbol: section.symbol,
                                isSelected: navigation.route.section == section
                            ) {
                                navigation.select(section: section)
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, Spacing.element)
            .padding(.top, Spacing.element)
        }
    }

    private func availableSections(for session: ServerSession) -> [ServerSection] {
        ServerSection.allCases.filter {
            !$0.isUtility && $0.isAvailable(given: session.capabilities)
        }
    }

    /// A count worth surfacing without opening the section — only where the
    /// number means something is wrong. A badge on everything is wallpaper.
    private func badge(for section: ServerSection, session: ServerSession) -> SidebarRow.Badge? {
        switch section {
        case .docker:
            let stopped = session.containers.filter(\.isStopped).count
            let unhealthy = session.containers.filter(\.isUnhealthy).count
            if unhealthy > 0 { return .init(count: unhealthy, tint: Palette.critical) }
            if stopped > 0 { return .init(count: stopped, tint: Palette.warning) }
            return nil
        case .services:
            let failed = session.services.filter(\.hasFailed).count
            return failed > 0 ? .init(count: failed, tint: Palette.critical) : nil
        default:
            return nil
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: Spacing.element) {
            Button(action: onAddServer) {
                HStack(spacing: Spacing.snug) {
                    Image(systemName: "plus").font(.system(size: 11, weight: .semibold))
                    Text("Add Server").font(Typography.secondary)
                }
                .foregroundStyle(Palette.accent)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .keyboardShortcut("n", modifiers: .command)

            Spacer()

            Button {
                navigation.go(to: .settings)
            } label: {
                Image(systemName: "gearshape")
                    .font(.system(size: 12))
                    .foregroundStyle(Palette.textSecondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Settings")
        }
        .padding(.horizontal, Spacing.group)
        .padding(.vertical, Spacing.element)
    }
}

// MARK: - Rows

public struct SidebarRow: View {
    public struct Badge {
        let count: Int
        let tint: Color
        public init(count: Int, tint: Color) {
            self.count = count
            self.tint = tint
        }
    }

    let title: String
    let symbol: String
    let isSelected: Bool
    var badge: Badge?
    let action: () -> Void

    public init(
        title: String,
        symbol: String,
        isSelected: Bool,
        badge: Badge? = nil,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.symbol = symbol
        self.isSelected = isSelected
        self.badge = badge
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: Spacing.element) {
                Image(systemName: symbol)
                    .font(.system(size: 12))
                    .frame(width: 18)
                    .foregroundStyle(isSelected ? Palette.accent : Palette.textSecondary)
                Text(title)
                    .font(Typography.body)
                    .foregroundStyle(isSelected ? Palette.textPrimary : Palette.textSecondary)
                Spacer(minLength: Spacing.tight)
                if let badge {
                    Text("\(badge.count)")
                        .font(Typography.metadata.weight(.semibold))
                        .monospacedDigit()
                        .foregroundStyle(badge.tint)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(badge.tint.opacity(0.14), in: Capsule())
                }
            }
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.snug)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .hoverHighlight(isSelected: isSelected)
        .accessibilityAddTraits(isSelected ? [.isSelected, .isButton] : .isButton)
        .accessibilityLabel(badge.map { "\(title), \($0.count) needing attention" } ?? title)
    }
}

/// A server in the fleet list: name, state, and the one number that matters.
public struct ServerSidebarRow: View {
    let summary: ServerSummary
    let health: ServerHealth
    let isSelected: Bool
    let action: () -> Void

    public init(summary: ServerSummary, health: ServerHealth, isSelected: Bool, action: @escaping () -> Void) {
        self.summary = summary
        self.health = health
        self.isSelected = isSelected
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: Spacing.element) {
                StatusDot(health.state, size: 9)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 0) {
                    Text(summary.name)
                        .font(Typography.body)
                        .foregroundStyle(isSelected ? Palette.textPrimary : Palette.textSecondary)
                        .lineLimit(1)
                    if summary.isDemo {
                        Text("Demo")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.informational)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.snug)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .hoverHighlight(isSelected: isSelected)
        .accessibilityAddTraits(isSelected ? [.isSelected, .isButton] : .isButton)
        .accessibilityLabel("\(summary.name), \(health.state.accessibilityLabel)")
        .help(health.summary)
    }
}
