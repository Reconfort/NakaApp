//  ServerDetailScreen.swift
//  ServerOS
//
//  The shell every server section renders inside.
//
//  From the brief: "When I click Production, I should feel like I've entered
//  that server." That feeling is built from three things, and this file owns all
//  three so no section has to re-make them:
//
//   1. A header that states, in one glance, which machine you are looking at and
//      what condition it is in. Name, verdict, then the quiet facts — the OS, the
//      architecture, the hostname, how long it has been up, which agent answers.
//   2. An honest gate. While the connection is still being made there is no
//      half-populated screen: a screen showing 0% CPU because nothing has
//      arrived yet is worse than a screen that says it is still connecting.
//      When the connection has failed, the failure is the screen.
//   3. Exactly the right live channels for the section on show. A window sitting
//      on Files should not be paying for container polling at the other end of
//      an SSH tunnel, so each section declares what it needs and gets that.
//
//  Everything below the header belongs to the section. This file dispatches and
//  then gets out of the way.

import AppKit
import Combine
import SwiftUI

/// The container for one server's sections: header, connection gate, dispatch.
public struct ServerDetailScreen: View {

    @Environment(AppModel.self) private var model

    private let session: ServerSession
    private let section: ServerSection
    private let navigation: NavigationModel

    /// Gate for "Remove from ServerOS", which is the one genuinely destructive
    /// thing this header can do.
    @State private var isConfirmingRemoval = false

    /// A removal that did not happen. The server is still there, and the user
    /// must not be left thinking otherwise.
    @State private var removalFailure: ServerOSError?

    public init(session: ServerSession, section: ServerSection, navigation: NavigationModel) {
        self.session = session
        self.section = section
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Palette.divider)

            if showsStaleBanner {
                StaleDataBanner(lastUpdated: session.lastContact) {
                    session.reconnect()
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.top, Spacing.group)
                .transition(.move(edge: .top).combined(with: .opacity))
            }

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .background(Palette.background)
        .animation(Motion.appear, value: showsStaleBanner)
        .onAppear { session.connect() }
        // Exactly the channels this section reads, and nothing else.
        .task(id: section) { session.need(channels: ServerDetailScreen.channels(for: section)) }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            Task { await session.refreshAll() }
        }
        .confirmDestructive(
            isPresented: $isConfirmingRemoval,
            title: "Remove \(session.name) from ServerOS?",
            target: session.name,
            consequence: "ServerOS will forget this server and delete its saved credential from your keychain. "
                + "The agent stays installed and running on the server itself, so nothing on \(session.name) stops.",
            isReversible: false,
            confirmTitle: "Remove Server"
        ) {
            // Leave first: the screen is about to lose the session it renders.
            navigation.forgetServer(id: session.id)
            Task {
                do { try await model.remove(id: session.id) }
                catch {
                    // The screen has already navigated away, so the failure has
                    // to surface at the fleet level or not at all. Reloading
                    // puts the still-present server back in the list rather than
                    // leaving the user believing it is gone.
                    removalFailure = .listChangeFailed(
                        what: "remove \(session.name)", underlying: error)
                    await model.load()
                }
            }
        }
        .sheet(item: $removalFailure) { failure in
            VStack(spacing: Spacing.section) {
                ErrorState(error: failure)
                Button("Close") { removalFailure = nil }
                    .buttonStyle(.primary)
            }
            .padding(Spacing.section)
            .frame(width: 460)
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.snug) {
                HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
                    Text(session.name)
                        .font(Typography.display)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                        .accessibilityAddTraits(.isHeader)

                    HealthBadge(session.health.state)

                    if session.isDemo {
                        // Demo data must never be mistakable for real
                        // infrastructure; the badge is permanent, not a hint.
                        Chip("Demo", tint: Palette.informational, systemImage: "wand.and.stars")
                    }
                }

                Text(metadataLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }

            Spacer(minLength: Spacing.group)

            actionsMenu
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    /// OS · architecture · hostname · uptime · agent. One quiet line: these are
    /// facts you check occasionally, not things to look at every day.
    private var metadataLine: String {
        var parts: [String] = []
        if let pretty = session.system?.os.pretty ?? session.summary.osPretty {
            parts.append(pretty)
        }
        if let arch = session.system?.architecture ?? session.summary.arch {
            parts.append(arch)
        }
        parts.append(session.summary.describedEndpoint)
        if let uptime = session.system?.uptimeSeconds, uptime > 0 {
            parts.append("up for \(Formatting.duration(seconds: uptime))")
        }
        if let version = session.agentVersion ?? session.system?.agent.version {
            parts.append("Agent \(version)")
        }
        return parts.joined(separator: "  ·  ")
    }

    private var actionsMenu: some View {
        Menu {
            Button("Reconnect") { session.reconnect() }
            Button("Copy Hostname") { copyHostname() }
            Button("Open Terminal") { navigation.select(section: .terminal) }
            Divider()
            Button("Remove from ServerOS…", role: .destructive) { isConfirmingRemoval = true }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.system(size: 15))
                .foregroundStyle(Palette.textSecondary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .frame(width: 30)
        .accessibilityLabel("Server actions")
    }

    private func copyHostname() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(session.summary.hostname, forType: .string)
    }

    // MARK: - Connection gate

    /// Stale data on screen must never be mistaken for live data.
    private var showsStaleBanner: Bool {
        !session.phase.isReady && session.lastContact != nil
    }

    @ViewBuilder
    private var content: some View {
        switch session.phase {
        case .failed(let error):
            ErrorState(error: error) { session.reconnect() }

        case .resolving, .connecting, .authenticating, .startingAgent:
            connectingState

        case .ready:
            sectionView

        case .idle, .disconnected:
            // Nothing in flight. If this server has answered before we keep its
            // last-known state on screen under the stale banner; if it never has,
            // there is genuinely nothing to show.
            if session.lastContact != nil {
                sectionView
            } else {
                notConnectedState
            }
        }
    }

    /// The steps, rather than a spinner: connecting involves a credential, an
    /// SSH tunnel and an agent handshake, and when it stalls the user needs to
    /// know which of those it stalled on.
    private var connectingState: some View {
        VStack(spacing: Spacing.group) {
            ProgressView().controlSize(.large)

            Text(session.phase.stepDescription(for: session.name))
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)
                .multilineTextAlignment(.center)

            StepProgress(steps: connectionSteps)
                .frame(maxWidth: 320, alignment: .leading)
                .padding(.top, Spacing.tight)
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(session.phase.stepDescription(for: session.name))
    }

    private var connectionSteps: [StepProgress.Step] {
        let order: [(String, String, ConnectionPhase)] = [
            ("credential", "Finding this server's credential", .resolving),
            ("tunnel", "Opening a secure connection", .connecting),
            ("auth", "Checking credentials", .authenticating),
            ("agent", "Waiting for the agent to answer", .startingAgent),
        ]
        let currentIndex = order.firstIndex { $0.2 == session.phase } ?? 0

        return order.enumerated().map { index, step in
            let status: StepProgress.Step.Status
            if index < currentIndex {
                status = .done
            } else if index == currentIndex {
                status = .active
            } else {
                status = .pending
            }
            return StepProgress.Step(id: step.0, title: step.1, status: status)
        }
    }

    private var notConnectedState: some View {
        EmptyState(
            systemImage: "bolt.horizontal.circle",
            title: "Not connected to \(session.name)",
            message: "ServerOS isn't talking to this server right now, so there is nothing current to show. "
                + "Connect to see its health, containers, services and logs.",
            actionTitle: "Connect",
            action: { session.connect() }
        )
    }

    // MARK: - Section dispatch

    @ViewBuilder
    private var sectionView: some View {
        switch section {
        case .overview:
            ServerOverviewSection(session: session, navigation: navigation)
        case .projects:
            ProjectsSection(session: session, navigation: navigation)
        case .docker:
            DockerSection(session: session, navigation: navigation)
        case .databases:
            DatabasesSection(session: session, navigation: navigation)
        case .services:
            ServicesSection(session: session, navigation: navigation)
        case .users:
            UsersSection(session: session, navigation: navigation)
        case .files:
            FilesSection(session: session, navigation: navigation)
        case .processes:
            ProcessesSection(session: session, navigation: navigation)
        case .logs:
            LogsSection(session: session, navigation: navigation)
        case .terminal:
            TerminalSection(session: session, navigation: navigation)
        }
    }

    /// What each section needs pushed to it over the live channel.
    ///
    /// Metrics are in every set because the header's verdict is computed from
    /// them, and a header that goes stale while the body is live would be a lie
    /// on every screen at once.
    static func channels(for section: ServerSection) -> Set<String> {
        switch section {
        case .overview:
            return ["metrics", "docker", "services", "activity"]
        case .docker, .projects:
            return ["metrics", "docker"]
        case .services:
            return ["metrics", "services"]
        case .databases, .users, .files, .processes, .logs, .terminal:
            return ["metrics"]
        }
    }
}

// MARK: - Preview

private struct ServerDetailPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()
    @State private var model = AppModel(store: ServerStore(container: ServerStore.emptyContainer()))

    var body: some View {
        ServerDetailScreen(session: session, section: .overview, navigation: navigation)
            .environment(model)
            .frame(width: 1000, height: 700)
    }
}

#Preview("Server detail") {
    ServerDetailPreviewHost()
}
