//  SettingsScreen.swift
//  ServerOS
//
//  WHY THIS SCREEN EXISTS
//
//  Settings in an infrastructure tool is not a junk drawer. It is where somebody
//  goes to answer three specific questions:
//
//    * "How do I make this app behave the way I want?"      → General
//    * "What is ServerOS actually connected to?"            → Servers
//    * "Where are my credentials, and can I revoke them?"   → Security
//
//  The Security tab is the one that earns the screen its place. A tool that
//  holds SSH keys and agent secrets has to be able to say, in plain words and
//  without the user taking anything on faith, exactly where those live, what
//  leaves the Mac, and how to destroy them. It is read-only apart from one
//  deliberate, confirmed, destructive action — which is the right shape for a
//  page about trust.
//
//  Preferences are stored in `UserDefaults` under keys prefixed with the bundle
//  identifier, so they are greppable, inspectable with `defaults read`, and
//  cannot collide with anything else on the system.

import AppKit
import SwiftData
import SwiftUI

// MARK: - Keys

/// Every preference key in one place, so a rename cannot silently orphan a
/// user's setting.
public enum SettingsKey {
    public static let appearance = "com.orionsystems.ServerOS.appearance"
    public static let metricInterval = "com.orionsystems.ServerOS.metricRefreshInterval"
    public static let connectAllAtLaunch = "com.orionsystems.ServerOS.connectAllAtLaunch"
    public static let confirmWithTouchID = "com.orionsystems.ServerOS.confirmDestructiveWithTouchID"
}

/// What this build of the app expects to be talking to.
public enum AgentRelease {
    /// The agent version this app was built and tested against.
    public static let expectedVersion = "0.1.0"
    /// The agent's HTTP API version this app speaks.
    public static let apiVersion = "1"
    public static let repository = "https://github.com/Reconfort/NakaApp"
}

/// How the app should look, independent of the system setting.
public enum AppearancePreference: String, CaseIterable, Hashable, Sendable {
    case system
    case light
    case dark

    public var title: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

// MARK: - Screen

/// The application's preferences.
public struct SettingsScreen: View {

    public init() {}

    public var body: some View {
        TabView {
            GeneralSettingsTab()
                .tabItem { Label("General", systemImage: "gearshape") }

            ServerSettingsTab()
                .tabItem { Label("Servers", systemImage: "server.rack") }

            SecuritySettingsTab()
                .tabItem { Label("Security", systemImage: "lock.shield") }

            AboutSettingsTab()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .tabViewStyle(.automatic)
        .frame(minWidth: 520, minHeight: 400)
        .background(Palette.background)
    }
}

// MARK: - General

private struct GeneralSettingsTab: View {

    @AppStorage(SettingsKey.appearance) private var appearanceRaw: String = AppearancePreference.system.rawValue
    @AppStorage(SettingsKey.metricInterval) private var metricInterval: Double = 2
    @AppStorage(SettingsKey.connectAllAtLaunch) private var connectAllAtLaunch: Bool = true
    @AppStorage(SettingsKey.confirmWithTouchID) private var confirmWithTouchID: Bool = false

    /// The intervals worth offering. A free-text field here would let somebody
    /// ask a production server for metrics a hundred times a second.
    private let intervals: [Double] = [1, 2, 5, 10, 30]

    var body: some View {
        Form {
            Section {
                Picker("Appearance", selection: appearanceBinding) {
                    ForEach(AppearancePreference.allCases, id: \.self) { option in
                        Text(option.title).tag(option)
                    }
                }
                .pickerStyle(.segmented)
            } header: {
                Text("Appearance").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("Light and dark are both designed rather than inverted, so either is a first-class way to use ServerOS.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Section {
                Picker("Update metrics every", selection: $metricInterval) {
                    ForEach(intervals, id: \.self) { value in
                        Text(intervalLabel(value)).tag(value)
                    }
                }
            } header: {
                Text("Metrics").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("How often a connected server reports CPU, memory, disk and network. A shorter interval feels livelier and asks more of the server. This takes effect the next time a server connects.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Section {
                Toggle("Connect to every server at launch", isOn: $connectAllAtLaunch)
                Toggle("Confirm destructive actions with Touch ID", isOn: $confirmWithTouchID)
            } header: {
                Text("Behaviour").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("Connecting at launch means the dashboard is accurate the moment you open it, at the cost of one SSH connection per server. Touch ID is asked for at the moment an action runs — deleting a server, removing a container, deleting a user — not when you open ServerOS.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }
        }
        .formStyle(.grouped)
        .task { applyAppearance(appearance) }
    }

    private var appearance: AppearancePreference {
        AppearancePreference(rawValue: appearanceRaw) ?? .system
    }

    /// A `Binding<AppearancePreference>` over the stored raw string, so the
    /// appearance is applied the instant it changes rather than at next launch.
    private var appearanceBinding: Binding<AppearancePreference> {
        Binding(
            get: { appearance },
            set: { newValue in
                appearanceRaw = newValue.rawValue
                applyAppearance(newValue)
            }
        )
    }

    /// Applied directly to `NSApplication` because a preference that does
    /// nothing until you click it again reads as a broken control.
    ///
    /// This applies it whenever this pane is on screen, which covers every case
    /// where the user changes it. Re-applying the stored choice at launch
    /// belongs to the app scene, which owns the application object — see
    /// `SettingsKey.appearance`.
    private func applyAppearance(_ preference: AppearancePreference) {
        switch preference {
        case .system: NSApplication.shared.appearance = nil
        case .light: NSApplication.shared.appearance = NSAppearance(named: .aqua)
        case .dark: NSApplication.shared.appearance = NSAppearance(named: .darkAqua)
        }
    }

    private func intervalLabel(_ seconds: Double) -> String {
        seconds == 1 ? "1 second" : "\(Int(seconds)) seconds"
    }
}

// MARK: - Servers

private struct ServerSettingsTab: View {

    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section {
                if model.servers.isEmpty {
                    Text("No servers are set up on this Mac yet.")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                } else {
                    ForEach(model.servers) { summary in
                        ServerSettingsRow(
                            summary: summary,
                            session: model.sessions[summary.id]
                        )
                    }
                }
            } header: {
                Text("Connected Servers").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("ServerOS is built and tested against agent \(AgentRelease.expectedVersion). A server running a different version usually still works, but new features may be missing and responses may not decode.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Section {
                Toggle("Show demo servers", isOn: demoBinding)
            } header: {
                Text("Demo Mode").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("Demo servers don't exist. Their hostnames are under .invalid, which can never resolve, and nothing they show ever touches a real machine. Turning this off removes them from ServerOS.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }
        }
        .formStyle(.grouped)
    }

    private var demoBinding: Binding<Bool> {
        Binding(
            get: { model.isShowingDemo },
            set: { shouldShow in
                Task {
                    do {
                        if shouldShow {
                            try await model.enableDemoMode()
                        } else {
                            try await model.disableDemoMode()
                        }
                    } catch {
                        // The toggle has already moved. Put it back by reloading
                        // from the store, so the switch reflects what is true.
                        await model.load()
                    }
                }
            }
        )
    }
}

private struct ServerSettingsRow: View {
    let summary: ServerSummary
    let session: ServerSession?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                HStack(spacing: Spacing.snug) {
                    Text(summary.name)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                    if summary.isDemo {
                        Chip("Demo", tint: Palette.informational, systemImage: "wand.and.stars")
                    }
                }
                Text(summary.describedEndpoint)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .textSelection(.enabled)
            }

            Spacer(minLength: Spacing.element)

            VStack(alignment: .trailing, spacing: Spacing.hairline) {
                Text(versionLabel)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                if isOutOfDate {
                    Chip(
                        "Agent out of date",
                        tint: Palette.warning,
                        systemImage: "exclamationmark.triangle.fill"
                    )
                }
            }
        }
        .padding(.vertical, Spacing.hairline)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(summary.name)
        .accessibilityValue(isOutOfDate ? "\(versionLabel), out of date" : versionLabel)
    }

    private var versionLabel: String {
        guard let version = session?.agentVersion else { return "Agent version unknown" }
        return "Agent \(version)"
    }

    /// Only claimed when the agent actually said which version it is. "Unknown"
    /// is not "out of date", and marking it as such would send people chasing a
    /// problem they do not have.
    private var isOutOfDate: Bool {
        guard let version = session?.agentVersion else { return false }
        return version != AgentRelease.expectedVersion
    }
}

// MARK: - Security

private struct SecuritySettingsTab: View {

    @Environment(AppModel.self) private var model

    /// Only the fingerprints, never the credentials. A `ServerCredential` holds
    /// an agent secret and an SSH private key, and those must never enter
    /// SwiftUI state — see the rules at the top of `ServerCredential.swift`.
    @State private var fingerprints: [String: String] = [:]
    @State private var isConfirmingForget = false

    /// Credentials this Mac was asked to forget and could not. Saying they are
    /// gone when they are still in the Keychain is the worst outcome here.
    @State private var forgetOutcome: ServerOSError?

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: Spacing.element) {
                    SecurityFact(
                        symbol: "key.fill",
                        text: "Every server's SSH key and agent secret is stored in this Mac's Keychain, under its own item, and nowhere else."
                    )
                    SecurityFact(
                        symbol: "icloud.slash",
                        text: "Nothing is synced. Credentials are not copied to iCloud and are not shared with another Mac."
                    )
                    SecurityFact(
                        symbol: "network.slash",
                        text: "No secret is ever sent to a ServerOS service. The agent's secret is generated on your server during setup and shared only with this Mac."
                    )
                    SecurityFact(
                        symbol: "signature",
                        text: "Requests carry a short-lived signature rather than the secret itself, so capturing one request gives an attacker nothing to reuse."
                    )
                }
            } header: {
                Text("Where Credentials Live").accessibilityAddTraits(.isHeader)
            }

            Section {
                if model.servers.isEmpty {
                    Text("No servers are set up on this Mac yet.")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                } else {
                    ForEach(model.servers) { summary in
                        VStack(alignment: .leading, spacing: Spacing.hairline) {
                            Text(summary.name)
                                .font(Typography.body)
                                .foregroundStyle(Palette.textPrimary)
                            Text(fingerprintLabel(for: summary))
                                .font(Typography.codeSmall)
                                .foregroundStyle(Palette.textSecondary)
                                .textSelection(.enabled)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .padding(.vertical, Spacing.hairline)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("\(summary.name) host key")
                        .accessibilityValue(fingerprintLabel(for: summary))
                    }
                }
            } header: {
                Text("Host Keys").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("ServerOS pins each server's host key the first time it connects and refuses to connect if it ever changes. Compare a fingerprint against your hosting panel if you want to verify a server independently.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Section {
                Button("Forget All Credentials") {
                    isConfirmingForget = true
                }
                .buttonStyle(.destructive)
                .disabled(model.servers.isEmpty)
            } header: {
                Text("Revoke").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("Removes every saved SSH key, password and agent secret from this Mac's Keychain. Your servers keep running and their agents stay installed — this Mac simply stops being able to reach them until each server is set up again.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }
        }
        .formStyle(.grouped)
        .task { await loadFingerprints() }
        .confirmDestructive(
            isPresented: $isConfirmingForget,
            title: "Forget every saved credential?",
            target: "all servers",
            consequence: """
            ServerOS will delete the SSH keys, passwords and agent secrets for all \(Formatting.count(model.servers.count)) servers from this Mac's Keychain.

            Nothing on the servers changes — the agents stay installed and running — but this Mac will not be able to connect to any of them until you set each one up again.
            """,
            isReversible: false,
            confirmTitle: "Forget All",
            perform: { forgetAllCredentials() }
        )
        .sheet(item: $forgetOutcome) { failure in
            VStack(spacing: Spacing.section) {
                ErrorState(error: failure)
                Button("Close") { forgetOutcome = nil }
                    .buttonStyle(.primary)
            }
            .padding(Spacing.section)
            .frame(width: 460)
        }
    }

    private func fingerprintLabel(for summary: ServerSummary) -> String {
        if summary.isDemo { return "Demo servers have no host key." }
        return fingerprints[summary.id] ?? "No host key recorded yet."
    }

    private func loadFingerprints() async {
        let store = CredentialStore()
        var found: [String: String] = [:]
        for summary in model.servers where !summary.isDemo {
            // The credential is read, the fingerprint is copied out of it, and
            // the credential itself goes out of scope immediately.
            if let credential = try? await store.load(serverID: summary.id),
               let fingerprint = credential.hostKeyFingerprint {
                found[summary.id] = fingerprint
            }
        }
        fingerprints = found
    }

    private func forgetAllCredentials() {
        let ids = model.servers.map(\.id)
        Task { @MainActor in
            let store = CredentialStore()
            var failed: [String] = []
            for id in ids {
                do { try await store.delete(serverID: id) }
                catch { failed.append(id) }
            }
            // Saying "credentials forgotten" when some are still in the Keychain
            // is the one outcome this screen must never produce.
            forgetOutcome = failed.isEmpty
                ? nil
                : .listChangeFailed(
                    what: "forget \(failed.count) of \(ids.count) saved credentials",
                    underlying: KeychainError.unexpectedStatus(errSecInternalError))
            await loadFingerprints()
        }
    }
}

private struct SecurityFact: View {
    let symbol: String
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
            Image(systemName: symbol)
                .font(.system(size: 11))
                .foregroundStyle(Palette.accent)
                .frame(width: 16)
                .accessibilityHidden(true)
            Text(text)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - About

private struct AboutSettingsTab: View {

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 0) {
                    KeyValueRow("ServerOS", appVersion)
                    KeyValueRow("Build", buildNumber, monospaced: true)
                    KeyValueRow("Agent API", AgentRelease.apiVersion, monospaced: true)
                    KeyValueRow("Expected agent", AgentRelease.expectedVersion, monospaced: true)
                }
            } header: {
                Text("Version").accessibilityAddTraits(.isHeader)
            }

            Section {
                if let url = URL(string: AgentRelease.repository) {
                    Link("ServerOS on GitHub", destination: url)
                        .font(Typography.body)
                } else {
                    Text(AgentRelease.repository)
                        .font(Typography.code)
                        .textSelection(.enabled)
                }
            } header: {
                Text("Source").accessibilityAddTraits(.isHeader)
            } footer: {
                Text("The macOS app, the control plane and the Linux agent are developed in one repository, so the wire contract between them can be reviewed as a single change.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Section {
                Text("ServerOS is distributed under the licence in the LICENSE file of the repository above. It bundles swift-nio-ssh and swift-crypto, whose own licences ship with the app.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("Licence").accessibilityAddTraits(.isHeader)
            }
        }
        .formStyle(.grouped)
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
    }

    private var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
    }
}

// MARK: - Previews

@MainActor
private func previewSettingsModel() -> AppModel {
    let container = try? ServerStore.makeContainer(inMemory: true)
    return AppModel(store: ServerStore(container: container ?? ServerStore.emptyContainer()))
}

#Preview("Settings") {
    let model = previewSettingsModel()
    SettingsScreen()
        .environment(model)
        .task { try? await model.enableDemoMode() }
        .frame(width: 580, height: 460)
}
