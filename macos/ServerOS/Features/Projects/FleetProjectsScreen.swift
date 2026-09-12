//  FleetProjectsScreen.swift
//  ServerOS
//
//  WHY THIS SCREEN EXISTS
//
//  A container list is a machine's view of the world. A *project* is the view a
//  person actually holds: "estatify" is one thing they deployed, not six
//  containers they have to reassemble in their head every time they look.
//
//  At fleet level the question this screen answers is specifically:
//  **where is each of my applications running, and is it whole?**
//
//  That is why the rows lead with "3 of 4 containers running" rather than with a
//  container count. A project with every container up and a project with one
//  container quietly exited look identical on a dashboard that only counts — and
//  the second one is usually the reason somebody opened the app.
//
//  Projects are grouped by server rather than merged into one flat list. Two
//  servers running the same compose project is the normal case (production and
//  staging), and a flat list would force the reader to carry "which machine is
//  this row on?" on every line.

import Combine
import SwiftData
import SwiftUI

/// Every Docker Compose project ServerOS can see, across every connected server.
public struct FleetProjectsScreen: View {

    @Environment(AppModel.self) private var model

    private let navigation: NavigationModel

    @State private var state: ScreenState<[ProjectGroup]> = .loading
    /// Set when some servers answered and others did not: the successes are
    /// still worth showing, but silently dropping a server would be dishonest.
    @State private var partialFailure: ServerOSError?
    /// Which of the four different nothings the empty state should explain.
    @State private var emptyKind: EmptyKind = .noProjects

    public init(navigation: NavigationModel) {
        self.navigation = navigation
    }

    public var body: some View {
        ScrollView {
            StatefulContent(state, retry: { reload() }) { groups in
                loaded(groups)
            } empty: {
                emptyState
            }
        }
        .background(Palette.background)
        .task(id: loadTrigger) { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            reload()
        }
    }

    // MARK: - Loaded

    private func loaded(_ groups: [ProjectGroup]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.section) {
            if let partialFailure {
                InlineBanner(
                    .warning,
                    "\(partialFailure.headline) Projects from the other servers are still shown below.",
                    actionTitle: "Try Again",
                    action: { reload() }
                )
            }

            ForEach(groups) { group in
                VStack(alignment: .leading, spacing: Spacing.group) {
                    SectionHeader(group.summary.name, count: group.projects.count) {
                        HealthBadge(group.health.state, compact: true)
                    }

                    VStack(spacing: 0) {
                        ForEach(group.projects) { project in
                            Button {
                                open(project, on: group.summary)
                            } label: {
                                ProjectRow(project: project)
                            }
                            .buttonStyle(.plain)
                            .hoverHighlight()

                            if project.id != group.projects.last?.id {
                                Divider().overlay(Palette.divider)
                            }
                        }
                    }
                    .padding(.vertical, Spacing.tight)
                    .cardSurface()
                }
            }
        }
        .readableWidth()
        .screenPadding()
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - Empty

    /// Four genuinely different nothings. "No data" would be true for all of
    /// them and useful for none, so each gets its own sentence and its own
    /// next step.
    ///
    /// Note that none of these is `ScreenState.unavailable`: that state's copy
    /// is written about one server ("Docker isn't available on this server"),
    /// and this screen is about all of them.
    enum EmptyKind {
        case noServers
        case notConnected
        case noDocker
        case noProjects
    }

    @ViewBuilder
    private var emptyState: some View {
        switch emptyKind {
        case .noServers:
            EmptyState(
                systemImage: "square.stack.3d.up",
                title: "No servers yet",
                message: "Projects are the applications running on your servers. Connect a server and ServerOS will find them.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )

        case .notConnected:
            EmptyState(
                systemImage: "bolt.horizontal.circle",
                title: "Not connected to any server",
                message: "ServerOS reads projects from each server's agent, so it needs at least one server to be reachable before it can list anything.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )

        case .noDocker:
            EmptyState(
                systemImage: "shippingbox",
                title: "No server is running Docker",
                message: "ServerOS finds projects from Docker Compose labels, so a server without Docker has none to find. Install Docker on a server and its projects appear here.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )

        case .noProjects:
            EmptyState(
                systemImage: "square.stack.3d.up",
                title: "No projects found",
                message: "ServerOS detects projects from the com.docker.compose.project label that Compose adds to every container it starts. Your servers are running Docker, but nothing on them carries those labels.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )
        }
    }

    // MARK: - Loading

    /// Changes whenever a server appears, gains Docker, or becomes reachable —
    /// so the listing reloads as the fleet comes up rather than sitting on a
    /// skeleton until the user does something.
    private var loadTrigger: String {
        model.servers.map { summary in
            let session = model.sessions[summary.id]
            let docker = session?.capabilities.docker == true ? "d" : "-"
            let ready = session?.phase.isReady == true ? "r" : "-"
            return "\(summary.id)\(docker)\(ready)"
        }
        .joined(separator: "|")
    }

    private var hasDockerCapableServer: Bool {
        model.servers.contains { model.sessions[$0.id]?.capabilities.docker == true }
    }

    private var isAnyServerStillConnecting: Bool {
        model.servers.contains { model.sessions[$0.id]?.phase.isWorking == true }
    }

    private var isAnyServerReady: Bool {
        model.servers.contains { model.sessions[$0.id]?.phase.isReady == true }
    }

    private func load() async {
        // Servers without Docker are skipped entirely rather than shown with an
        // error: a box with no Docker has no projects, and that is not a fault.
        let targets: [(summary: ServerSummary, api: any AgentAPI)] = model.servers.compactMap { summary in
            guard let session = model.sessions[summary.id],
                  session.capabilities.docker,
                  let api = session.api else { return nil }
            return (summary, api)
        }

        guard !targets.isEmpty else {
            partialFailure = nil
            if model.servers.isEmpty {
                emptyKind = .noServers
                state = .empty
            } else if isAnyServerStillConnecting || (hasDockerCapableServer && !isAnyServerReady) {
                state = .loading
            } else if isAnyServerReady {
                emptyKind = .noDocker
                state = .empty
            } else {
                emptyKind = .notConnected
                state = .empty
            }
            return
        }

        var groups: [ProjectGroup] = []
        var failure: ServerOSError?

        for target in targets {
            do {
                let list = try await target.api.projects()
                guard !list.items.isEmpty else { continue }
                groups.append(ProjectGroup(
                    summary: target.summary,
                    health: model.sessions[target.summary.id]?.health ?? .unknown,
                    projects: list.items
                ))
            } catch let error as ServerOSError {
                failure = error
            } catch {
                failure = ServerOSError.transport(error, serverName: target.summary.name)
            }
        }

        if groups.isEmpty {
            partialFailure = nil
            if let failure {
                state = .failed(failure)
            } else {
                emptyKind = .noProjects
                state = .empty
            }
        } else {
            partialFailure = failure
            state = .loaded(groups)
        }
    }

    private func reload() {
        Task { await load() }
    }

    private func open(_ project: Project, on summary: ServerSummary) {
        navigation.selectedProjectName = project.name
        navigation.enter(serverID: summary.id, section: .projects)
    }
}

// MARK: - Group

/// One server's projects.
private struct ProjectGroup: Identifiable {
    let summary: ServerSummary
    let health: ServerHealth
    let projects: [Project]
    var id: String { summary.id }
}

// MARK: - Row

private struct ProjectRow: View {
    let project: Project

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            Image(systemName: "square.stack.3d.up")
                .font(.system(size: 13))
                .foregroundStyle(Palette.textSecondary)
                .frame(width: 18)
                .padding(.top, 1)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.tight) {
                HStack(spacing: Spacing.element) {
                    Text(project.name)
                        .font(Typography.body.weight(.medium))
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                    statePill
                }

                Text(containerSummary)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)

                if !services.isEmpty {
                    HStack(spacing: Spacing.tight) {
                        ForEach(services, id: \.self) { service in
                            Chip(service)
                        }
                    }
                }

                if let directory = project.workingDir {
                    Text(directory)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                        .truncationMode(.head)
                }
            }

            Spacer(minLength: Spacing.element)

            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)
        }
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.element)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(project.name)
        .accessibilityValue("\(stateWord). \(containerSummary)")
        .accessibilityAddTraits(.isButton)
    }

    /// `RunPill` covers on and off. A compose project can also be *partly* up,
    /// which none of the pill's words describes honestly — "Restarting" and
    /// "Failed" would both be wrong — so that one state gets a warning `Chip`
    /// instead. Colour is still paired with a glyph and a word either way.
    @ViewBuilder
    private var statePill: some View {
        if project.isPartiallyRunning {
            Chip("Degraded", tint: Palette.warning, systemImage: "exclamationmark.triangle.fill")
        } else {
            RunPill(RunPill.RunState.fromService(project.state))
        }
    }

    private var stateWord: String {
        if project.isPartiallyRunning { return "Degraded" }
        return RunPill.RunState.fromService(project.state).label
    }

    private var containerSummary: String {
        let total = project.containerCount
        guard total > 0 else { return "No containers" }
        return "\(project.running) of \(total) container\(total == 1 ? "" : "s") running"
    }

    /// Compose can list the same service twice across containers; duplicate ids
    /// in a `ForEach` are a real bug, so dedupe while keeping declared order.
    private var services: [String] {
        var seen = Set<String>()
        return project.services.filter { seen.insert($0).inserted }
    }
}

// MARK: - Previews

@MainActor
private func previewProjectsModel() -> AppModel {
    let container = try? ServerStore.makeContainer(inMemory: true)
    return AppModel(store: ServerStore(container: container ?? ServerStore.emptyContainer()))
}

#Preview("Projects — demo fleet") {
    let model = previewProjectsModel()
    FleetProjectsScreen(navigation: NavigationModel())
        .environment(model)
        .task { try? await model.enableDemoMode() }
        .frame(width: 960, height: 640)
}
