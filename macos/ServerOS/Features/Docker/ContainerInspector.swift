//  ContainerInspector.swift
//  ServerOS
//
//  Everything about one container, in the order a person actually needs it.
//
//  This pane is the clearest test of the brief's progressive-disclosure rule:
//  "don't hide the technical depth, but don't lead with it either". A Docker
//  container has roughly sixty inspectable facts. Showing all sixty is `docker
//  inspect`, which already exists and is free. Showing six is a toy. So the
//  pane has four levels, and each one answers a different question:
//
//    Default      "Is it up, and is it healthy?"          — always visible
//    Details      "How is it configured?"                 — open by default
//    Environment  "What was it given?"                    — its own group
//    Advanced     "What exactly am I looking at?"         — collapsed
//
//  The environment group is the one with a real decision in it. The agent masks
//  values that look like secrets and tells us it did, so `masked == true` and
//  `value == nil` mean "deliberately withheld", never "empty". Rendering that
//  as a blank cell would read as a bug and quietly teach people that ServerOS
//  loses data. It gets a lock and the word "Hidden" instead, and revealing it
//  is a decision the user makes knowingly: the reveal is a separate, audited
//  request to the server, and the confirmation says so, because someone about
//  to put a production database password on a screen in an open-plan office
//  deserves to know that it will also appear in the server's activity log.

import SwiftUI

/// The inspector for one container, shown beside the Docker list.
struct ContainerInspector: View {

    /// How often the pane re-samples CPU and memory. One container, one round
    /// trip — cheap enough to be live, unlike sampling the whole list.
    private static let statsInterval: Duration = .seconds(5)

    let containerID: String
    let session: ServerSession
    let onClose: () -> Void

    @State private var state: ScreenState<DockerContainerDetail> = .loading
    @State private var stats: DockerStats?
    /// Whether the detail is being fetched with secret values unmasked.
    @State private var isRevealing = false
    @State private var isConfirmingReveal = false
    @State private var showsDetails = true
    @State private var showsEnvironment = true
    @State private var showsAdvanced = false
    @State private var isShowingLogs = false
    @State private var reloadNonce = 0

    init(containerID: String, session: ServerSession, onClose: @escaping () -> Void) {
        self.containerID = containerID
        self.session = session
        self.onClose = onClose
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Palette.divider)

            ScrollView {
                StatefulContent(state, retry: { reloadNonce += 1 }) { detail in
                    detailBody(detail)
                } empty: {
                    missingState
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Palette.surface)
        // Re-fetch when the selected container changes, and again when the user
        // asks for unmasked values — the reveal is a different request, not a
        // different rendering of the same one.
        .task(id: loadKey) { await load() }
        .task(id: containerID) { await pollStats() }
        .sheet(isPresented: $isShowingLogs) {
            ContainerLogsView(
                containerID: containerID,
                containerName: title,
                session: session
            )
        }
        // Not a destructive confirmation: nothing is lost, and dressing it in
        // red would blunt the colour that means "this cannot be undone". It is
        // still a confirmation, because putting secrets on a screen is a
        // decision with consequences outside this app.
        .confirmationDialog(
            "Reveal hidden values?",
            isPresented: $isConfirmingReveal,
            titleVisibility: .visible
        ) {
            Button("Reveal Values") { isRevealing = true }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "Secrets such as database passwords and API keys will appear on screen in plain text. "
                + "ServerOS asks \(session.name) for them, and the server records that request in its "
                + "activity log."
            )
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                Text(title)
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .accessibilityAddTraits(.isHeader)

                Spacer(minLength: Spacing.element)

                Button(action: onClose) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(Palette.textMuted)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Close the inspector")
            }

            HStack(spacing: Spacing.element) {
                RunPill(runState)

                if let project = projectName {
                    Chip(project, tint: Palette.accent, systemImage: "square.stack.3d.up")
                }

                Spacer(minLength: Spacing.element)

                Button("Logs") { isShowingLogs = true }
                    .buttonStyle(.secondary)
                    .accessibilityLabel("Open this container's logs")
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.top, Spacing.card)
        .padding(.bottom, Spacing.element)
    }

    /// The compose service name where there is one, because `estatify-api-1` is
    /// a name Docker invented and `api` is the name a person chose.
    private var title: String {
        if let detail = state.value {
            return detail.composeService ?? detail.name
        }
        return liveContainer?.displayName ?? "Container"
    }

    private var projectName: String? {
        state.value?.composeProject ?? liveContainer?.composeProject
    }

    /// The live list is fresher than a detail fetched a minute ago, so the pill
    /// at the top of the pane follows the stream rather than the snapshot.
    private var runState: RunPill.RunState {
        if let live = liveContainer {
            return RunPill.RunState.fromContainer(live.state)
        }
        if let detail = state.value {
            return RunPill.RunState.fromContainer(detail.state)
        }
        return .unknown
    }

    private var liveContainer: DockerContainer? {
        session.containers.first {
            $0.id == containerID || $0.shortID == containerID || $0.name == containerID
        }
    }

    // MARK: - Body

    private func detailBody(_ detail: DockerContainerDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            summarySection(detail)

            Divider().overlay(Palette.divider)

            DisclosureGroup(isExpanded: $showsDetails) {
                detailsSection(detail)
            } label: {
                groupLabel("Details", systemImage: "slider.horizontal.3")
            }

            Divider().overlay(Palette.divider)

            DisclosureGroup(isExpanded: $showsEnvironment) {
                environmentSection(detail)
            } label: {
                groupLabel("Environment", systemImage: "key")
            }

            Divider().overlay(Palette.divider)

            DisclosureGroup(isExpanded: $showsAdvanced) {
                advancedSection(detail)
            } label: {
                groupLabel("Advanced", systemImage: "wrench.and.screwdriver")
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Level 1 — the default

    private func summarySection(_ detail: DockerContainerDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            Text(detail.image)
                .font(Typography.code)
                .foregroundStyle(Palette.textSecondary)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
                .accessibilityLabel("Image")
                .accessibilityValue(detail.image)

            HStack(alignment: .top, spacing: Spacing.section) {
                MetricTile(label: "CPU", value: stats?.cpuPercent, caption: cpuCaption)
                MetricTile(label: "Memory", value: stats?.memoryPercent, caption: memoryCaption)
                Spacer(minLength: 0)
            }

            if !detail.ports.isEmpty {
                portsView(detail.ports)
            }

            VStack(alignment: .leading, spacing: 0) {
                KeyValueRow("Uptime", uptimeText(detail))
                KeyValueRow("Restarts", detail.restartCount.map { Formatting.count($0) } ?? "—")
                KeyValueRow("Health", healthText(detail))
            }
        }
    }

    private var cpuCaption: String? {
        guard let cores = stats?.onlineCPUs, cores > 0 else { return nil }
        return "\(cores) core\(cores == 1 ? "" : "s") available"
    }

    private var memoryCaption: String? {
        guard let stats else { return nil }
        return Formatting.usage(used: stats.memoryBytes, total: stats.memoryLimitBytes)
    }

    private func uptimeText(_ detail: DockerContainerDetail) -> String {
        guard detail.isRunning, let started = detail.startedAt, started > 0 else {
            return Formatting.containerState(detail.state, status: detail.status)
        }
        let seconds = Int(Date().timeIntervalSince1970) - Int(started)
        return seconds > 0 ? Formatting.duration(seconds: seconds) : "Just started"
    }

    /// "No health check" is a real and common answer, and it is not the same as
    /// "unhealthy" — so it is said in words rather than left blank.
    private func healthText(_ detail: DockerContainerDetail) -> String {
        guard let health = detail.health, !health.isEmpty, health != "none" else {
            return "No health check defined"
        }
        switch health {
        case "healthy": return "Healthy"
        case "unhealthy":
            if let streak = detail.healthCheck?.failingStreak, streak > 0 {
                return "Unhealthy after \(Formatting.count(streak)) failed check\(streak == 1 ? "" : "s")"
            }
            return "Unhealthy"
        case "starting": return "Starting up"
        default: return health.capitalizingFirstLetter()
        }
    }

    /// A wrapping row of port chips.
    ///
    /// An adaptive grid rather than a custom `Layout`: ports are short and
    /// similar in width, so equal columns look deliberate here and save a
    /// layout implementation that would exist for one row of chips.
    private func portsView(_ ports: [DockerPort]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text("Ports")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .textCase(.uppercase)
                .tracking(0.4)

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 96), spacing: Spacing.tight, alignment: .leading)],
                alignment: .leading,
                spacing: Spacing.tight
            ) {
                ForEach(ports) { port in
                    Chip(port.describedMapping, tint: Palette.informational)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Ports")
        .accessibilityValue(ports.map(\.describedMapping).joined(separator: ", "))
    }

    // MARK: Level 2 — details

    private func detailsSection(_ detail: DockerContainerDetail) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("Command", ContainerInspector.joined(detail.command), monospaced: true)
            KeyValueRow("Entry Point", ContainerInspector.joined(detail.entrypoint), monospaced: true)
            KeyValueRow("Working Directory", ContainerInspector.orDash(detail.workingDir), monospaced: true)
            KeyValueRow("User", ContainerInspector.orDash(detail.user))
            KeyValueRow("Platform", ContainerInspector.orDash(detail.platform))
            KeyValueRow("Restart Policy", detail.restartPolicy?.described ?? "Never")

            networksView(detail)
            mountsView(detail)
            healthCheckView(detail)
        }
        .padding(.top, Spacing.element)
    }

    @ViewBuilder
    private func networksView(_ detail: DockerContainerDetail) -> some View {
        if let networks = detail.networks, !networks.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                subheading("Networks")
                ForEach(networks) { network in
                    VStack(alignment: .leading, spacing: 0) {
                        Text(network.name)
                            .font(Typography.body)
                            .foregroundStyle(Palette.textPrimary)
                            .lineLimit(1)
                        Text(ContainerInspector.describe(network))
                            .font(Typography.codeSmall)
                            .foregroundStyle(Palette.textMuted)
                            .textSelection(.enabled)
                            .lineLimit(2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 2)
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(.top, Spacing.element)
        }
    }

    @ViewBuilder
    private func mountsView(_ detail: DockerContainerDetail) -> some View {
        if let mounts = detail.mounts, !mounts.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                subheading("Mounts")
                ForEach(mounts) { mount in
                    VStack(alignment: .leading, spacing: Spacing.hairline) {
                        Text("\(ContainerInspector.orDash(mount.source)) → \(mount.destination)")
                            .font(Typography.codeSmall)
                            .foregroundStyle(Palette.textPrimary)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        HStack(spacing: Spacing.tight) {
                            Chip(mount.type.capitalizingFirstLetter(), tint: Palette.inactive)
                            // Read-only mounts are the reason a container that
                            // "should" be able to write cannot, so the mode is
                            // stated rather than implied.
                            Chip(
                                mount.rw == false ? "Read only" : "Read write",
                                tint: mount.rw == false ? Palette.warning : Palette.inactive
                            )
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 2)
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(.top, Spacing.element)
        }
    }

    @ViewBuilder
    private func healthCheckView(_ detail: DockerContainerDetail) -> some View {
        if let check = detail.healthCheck, check.status != nil || check.test != nil {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                subheading("Health Check")
                KeyValueRow("Status", ContainerInspector.orDash(check.status))
                KeyValueRow("Failing Streak", check.failingStreak.map { Formatting.count($0) } ?? "—")
                if let test = check.test, !test.isEmpty {
                    Text(test.joined(separator: " "))
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .textSelection(.enabled)
                        .lineLimit(4)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityLabel("Health check command")
                        .accessibilityValue(test.joined(separator: " "))
                }
            }
            .padding(.top, Spacing.element)
        }
    }

    // MARK: Level 3 — environment

    @ViewBuilder
    private func environmentSection(_ detail: DockerContainerDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            if let env = detail.env, !env.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(env) { variable in
                        EnvironmentRow(variable: variable)
                    }
                }

                if isRevealing {
                    InlineBanner(
                        .warning,
                        "Secret values are visible, and \(session.name) recorded this reveal in its activity log.",
                        actionTitle: "Hide Again"
                    ) {
                        isRevealing = false
                    }
                } else if env.contains(where: \.masked) {
                    VStack(alignment: .leading, spacing: Spacing.snug) {
                        Text("Values that look like secrets are withheld by the agent, not by this Mac.")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Reveal Values…") { isConfirmingReveal = true }
                            .buttonStyle(.secondary)
                    }
                }
            } else {
                Text("This container was started without any environment variables.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.top, Spacing.element)
    }

    // MARK: Level 4 — advanced

    private func advancedSection(_ detail: DockerContainerDetail) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("Container ID", detail.id, monospaced: true, selectable: true)
            KeyValueRow("Short ID", detail.shortID, monospaced: true, selectable: true)
            KeyValueRow("Docker Name", detail.name, monospaced: true, selectable: true)
            KeyValueRow("Image ID", ContainerInspector.orDash(detail.imageID), monospaced: true, selectable: true)
            KeyValueRow("Compose Project", ContainerInspector.orDash(detail.composeProject))
            KeyValueRow("Compose Service", ContainerInspector.orDash(detail.composeService))
            KeyValueRow("Raw State", "\(detail.state) · \(detail.status)", monospaced: true)
            KeyValueRow("Created", Formatting.timestamp(unixSeconds: detail.createdAt))
            KeyValueRow("Started", Formatting.timestamp(unixSeconds: detail.startedAt))
            KeyValueRow("Finished", Formatting.timestamp(unixSeconds: detail.finishedAt))
            KeyValueRow("Exit Code", detail.exitCode.map { String($0) } ?? "—")
            KeyValueRow("TTY", detail.tty.map { $0 ? "Yes" : "No" } ?? "—")

            labelsView(detail)
        }
        .padding(.top, Spacing.element)
    }

    @ViewBuilder
    private func labelsView(_ detail: DockerContainerDetail) -> some View {
        if let labels = detail.labels, !labels.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                subheading("Labels")
                ForEach(labels.keys.sorted(), id: \.self) { key in
                    HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                        Text(key)
                            .font(Typography.codeSmall)
                            .foregroundStyle(Palette.textSecondary)
                            .frame(width: 132, alignment: .leading)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(labels[key] ?? "")
                            .font(Typography.codeSmall)
                            .foregroundStyle(Palette.textPrimary)
                            .textSelection(.enabled)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 1)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(key)
                    .accessibilityValue(labels[key] ?? "Empty")
                }
            }
            .padding(.top, Spacing.element)
        }
    }

    // MARK: - Shared pieces

    private func groupLabel(_ title: String, systemImage: String) -> some View {
        HStack(spacing: Spacing.snug) {
            Image(systemName: systemImage)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)
            Text(title)
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    private func subheading(_ title: String) -> some View {
        Text(title)
            .font(Typography.metadata)
            .foregroundStyle(Palette.textSecondary)
            .textCase(.uppercase)
            .tracking(0.4)
            .padding(.top, Spacing.tight)
            .accessibilityAddTraits(.isHeader)
    }

    private var missingState: some View {
        EmptyState(
            systemImage: "questionmark.folder",
            title: "This container isn't here any more",
            message: "\(session.name) no longer has a container with this id. It may have been removed or replaced by a new deployment.",
            actionTitle: "Close",
            action: onClose
        )
    }

    // MARK: - Loading

    /// What makes the pane ask again: a different container, a reveal, a retry.
    private struct InspectorLoad: Equatable {
        let containerID: String
        let isRevealing: Bool
        let nonce: Int
        let isReady: Bool
    }

    private var loadKey: InspectorLoad {
        InspectorLoad(
            containerID: containerID,
            isRevealing: isRevealing,
            nonce: reloadNonce,
            isReady: session.phase.isReady
        )
    }

    private func load() async {
        guard let api = session.api else {
            if state.value == nil { state = .loading }
            return
        }
        guard session.capabilities.docker else {
            state = .unavailable(
                subsystem: "Docker",
                reason: "\(session.name) isn't running a Docker daemon that the agent can reach."
            )
            return
        }
        if state.value == nil { state = .loading }

        do {
            let detail = try await api.container(id: containerID, revealEnvironment: isRevealing)
            state = .loaded(detail)
        } catch let error as ServerOSError {
            // A container that has just been removed is not a broken app; it is
            // a pane pointing at something that is gone.
            state = error.code == "not_found" ? .empty : .failed(error)
        } catch {
            state = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func pollStats() async {
        guard let api = session.api, session.capabilities.docker else { return }
        while !Task.isCancelled {
            if liveContainer?.isRunning ?? true {
                stats = try? await api.containerStats(id: containerID)
            } else {
                // A stopped container has no stats, and a dash is the honest
                // rendering of that — not a zero.
                stats = nil
            }
            try? await Task.sleep(for: ContainerInspector.statsInterval)
        }
    }

    // MARK: - Formatting helpers

    /// File-scoped so a sibling screen cannot pick these up by accident.
    fileprivate static func orDash(_ value: String?) -> String {
        guard let value, !value.isEmpty else { return "—" }
        return value
    }

    fileprivate static func joined(_ parts: [String]?) -> String {
        guard let parts, !parts.isEmpty else { return "—" }
        return parts.joined(separator: " ")
    }

    fileprivate static func describe(_ network: DockerNetworkAttachment) -> String {
        var parts: [String] = []
        if let ip = network.ipAddress, !ip.isEmpty { parts.append(ip) }
        if let gateway = network.gateway, !gateway.isEmpty { parts.append("gateway \(gateway)") }
        if let mac = network.macAddress, !mac.isEmpty { parts.append(mac) }
        return parts.isEmpty ? "No address assigned" : parts.joined(separator: "  ·  ")
    }
}

// MARK: - One environment variable

/// A key and its value — or a deliberate, visible absence.
///
/// `masked` is the whole reason this is a type rather than a `KeyValueRow`: a
/// withheld secret must look withheld. An empty cell would read as a bug, and a
/// row of asterisks would suggest the value is stored here and merely obscured,
/// which it is not — the agent never sent it.
private struct EnvironmentRow: View {
    let variable: DockerEnvVar

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
            Text(variable.key)
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textSecondary)
                .frame(width: 132, alignment: .leading)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(variable.key)

            if variable.masked {
                HStack(spacing: Spacing.tight) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Palette.warning)
                        .accessibilityHidden(true)
                    Chip("Hidden", tint: Palette.warning)
                }
            } else {
                Text(displayValue)
                    .font(Typography.codeSmall)
                    .foregroundStyle(variable.value == nil ? Palette.textMuted : Palette.textPrimary)
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(variable.key)
        .accessibilityValue(
            variable.masked
                ? "Hidden. Reveal values to show this."
                : (variable.value?.isEmpty == false ? variable.value! : "Empty")
        )
    }

    private var displayValue: String {
        guard let value = variable.value, !value.isEmpty else { return "—" }
        return value
    }
}

// MARK: - Preview

private struct ContainerInspectorPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var containerID: String?

    var body: some View {
        Group {
            if let containerID {
                ContainerInspector(containerID: containerID, session: session, onClose: {})
            } else {
                // The preview has to wait for the demo stream's first frame
                // before it knows a real container id to inspect.
                InlineProgress("Starting the demo server…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(width: 380, height: 720)
        .background(Palette.background)
        .task {
            session.connect()
            while containerID == nil && !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(200))
                containerID = session.containers.first?.id
            }
        }
    }
}

#Preview("Container inspector") {
    ContainerInspectorPreviewHost()
}
