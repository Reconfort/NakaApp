//  AddServerFlow.swift
//  ServerOS
//
//  WHY THIS FLOW EXISTS
//
//  This is the most important thirty seconds in the product. Everything else in
//  ServerOS is a view onto a server that is already set up; this is where a
//  machine the app has never seen becomes one it manages. It runs once per
//  server, over SSH, with administrator rights, against infrastructure somebody
//  cares about — and if it goes wrong halfway, the user needs to know exactly
//  which half.
//
//  Four decisions shape the whole flow:
//
//  1. **Every step is named and shown.** A spinner that says "Setting up…" for
//     ninety seconds and then fails is unrecoverable for the user. Naming the
//     steps means a failure has an address: "installing the agent" is a
//     different problem, with a different fix, from "pairing this Mac".
//
//  2. **The recommended path is a key ServerOS owns.** It installs one line in
//     `authorized_keys`, is revocable without touching how the person logs in
//     themselves, and means no password is stored anywhere. That is the default
//     and the copy says why.
//
//  3. **The host key is confirmed by a human, once.** Trust on first use is a
//     real compromise and the user is told what it protects rather than being
//     shown a fingerprint as a formality.
//
//  4. **Nothing typed is ever lost.** A failure keeps the completed steps
//     ticked, keeps the fields, and offers Try Again — because the most likely
//     failures here (a wrong password, a server without passwordless sudo, a
//     download that could not reach the CDN) are all things the user fixes in
//     ten seconds and retries.

import AppKit
import Foundation
import NIOSSH
import Observation
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Result summary

/// What the Done step shows.
///
/// Deliberately a separate, secret-free value rather than the `BootstrapResult`
/// itself: that carries the agent secret and the generated private key, and
/// those must never live in observable UI state. See `ServerCredential.swift`.
public struct ServerSetupSummary: Sendable, Equatable {
    public let serverID: String
    public let osPretty: String
    public let architecture: String
    public let kernel: String
    public let agentVersion: String
    public let hostKeyFingerprint: String
    public let installedOwnKey: Bool
    public let warnings: [String]
}

// MARK: - Model

/// The state behind the Add Server sheet.
///
/// `@Observable` and `@MainActor` because it exists to be read by SwiftUI while
/// an actor (`SSHClient`, `AgentBootstrap`) does the work behind it.
@MainActor
@Observable
public final class AddServerModel {

    /// Where the sheet is.
    public enum Step: Int, CaseIterable, Hashable, Sendable {
        case details
        case authentication
        case connecting
        case done

        public var title: String {
            switch self {
            case .details: return "Server Details"
            case .authentication: return "Authentication"
            case .connecting: return "Setting Up"
            case .done: return "Ready"
            }
        }
    }

    /// How ServerOS proves who it is for this one setup run.
    public enum AuthenticationMethod: String, CaseIterable, Hashable, Sendable {
        case password
        case existingKey

        public var title: String {
            switch self {
            case .password: return "Password"
            case .existingKey: return "Existing private key"
            }
        }
    }

    // MARK: Details

    public var name = ""
    public var host = ""
    public var portText = "22"
    public var username = ""

    // MARK: Authentication

    public var method: AuthenticationMethod = .password

    /// Bound to a `SecureField`. Held only for the length of this sheet, and
    /// written to the Keychain only if the user explicitly opts in below.
    public var password = ""

    /// Whether to save the password so ServerOS can reconnect later. Off by
    /// default, and forced on when there is no key to fall back to.
    public var savesPassword = false

    /// The recommended path: ServerOS mints its own Ed25519 key, installs it in
    /// `authorized_keys`, and uses it for every future connection.
    public var installsOwnKey = true

    public private(set) var keyFileName: String?
    public private(set) var keyDescription: String?
    public private(set) var keyError: ServerOSError?

    /// Raw private key material. `@ObservationIgnored` on purpose: observable
    /// properties end up in diagnostics, previews and state dumps, and key
    /// material must not. The UI reads `keyDescription` instead.
    @ObservationIgnored private var parsedKey: ParsedPrivateKey?

    // MARK: Progress

    public private(set) var step: Step = .details
    public private(set) var isWorking = false
    public private(set) var failure: ServerOSError?
    public private(set) var currentBootstrapStep: BootstrapStep?
    public private(set) var hasFinishedBootstrap = false

    // MARK: Host key

    public private(set) var observedFingerprint: String?
    public private(set) var isAwaitingHostKeyConfirmation = false

    // MARK: Outcome

    public private(set) var setupSummary: ServerSetupSummary?

    /// Carries the agent secret and the generated key. Never observed.
    @ObservationIgnored private var bootstrapResult: BootstrapResult?
    @ObservationIgnored private var client: SSHClient?
    @ObservationIgnored private var work: Task<Void, Never>?

    public init() {}

    // MARK: - Validation

    public var trimmedName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    public var trimmedHost: String { host.trimmingCharacters(in: .whitespacesAndNewlines) }
    public var trimmedUsername: String { username.trimmingCharacters(in: .whitespacesAndNewlines) }

    public var nameError: String? {
        trimmedName.isEmpty ? "A name is required. It's only used on this Mac." : nil
    }

    public var hostError: String? {
        if trimmedHost.isEmpty { return "A host is required." }
        if trimmedHost.contains("://") || trimmedHost.contains("/") {
            return "Enter a hostname or IP address on its own — no http:// and no path."
        }
        if trimmedHost.contains(" ") { return "A hostname can't contain spaces." }
        return nil
    }

    public var portError: String? {
        let trimmed = portText.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "A port is required. SSH usually listens on 22." }
        guard let value = Int(trimmed) else { return "A port is a number between 1 and 65535." }
        guard (1...65535).contains(value) else { return "Port must be between 1 and 65535." }
        return nil
    }

    public var usernameError: String? {
        trimmedUsername.isEmpty
            ? "A username is required. This is the account ServerOS logs in as."
            : nil
    }

    public var detailsAreValid: Bool {
        nameError == nil && hostError == nil && portError == nil && usernameError == nil
    }

    public var port: Int {
        Int(portText.trimmingCharacters(in: .whitespaces)) ?? 22
    }

    /// An imported ECDSA key can authenticate this one setup run, but ServerOS
    /// stores reusable keys as 32-byte Ed25519 seeds — so it cannot keep a
    /// P-256 key for later, and must mint one of its own.
    public var mustInstallOwnKey: Bool {
        guard method == .existingKey, let key = parsedKey else { return false }
        if case .p256 = key { return true }
        return false
    }

    /// With no key installed, a password is the only way back in, so it has to
    /// be saved or the server becomes unreachable the moment this sheet closes.
    public var mustSavePassword: Bool {
        method == .password && !installsOwnKey
    }

    public var authenticationIsValid: Bool {
        switch method {
        case .password: return !password.isEmpty
        case .existingKey: return parsedKey != nil
        }
    }

    // MARK: - Steps shown

    /// The steps this run will actually perform. Installing a key is skipped
    /// entirely when ServerOS is not installing one, and showing a step that
    /// never runs would leave a permanently pending row.
    public var plannedSteps: [BootstrapStep] {
        var order = BootstrapStep.progressOrder.filter { $0 != .done }
        if !willInstallOwnKey {
            order.removeAll { $0 == .installingKey }
        }
        return order
    }

    public var willInstallOwnKey: Bool {
        installsOwnKey || mustInstallOwnKey
    }

    public func progressSteps() -> [StepProgress.Step] {
        let order = plannedSteps
        let currentIndex = currentBootstrapStep.flatMap { order.firstIndex(of: $0) }

        return order.enumerated().map { index, bootstrapStep in
            let status: StepProgress.Step.Status
            if let currentIndex {
                if index < currentIndex {
                    status = .done
                } else if index == currentIndex {
                    if failure != nil {
                        status = .failed
                    } else if isAwaitingHostKeyConfirmation {
                        // The connection succeeded; what is outstanding is the
                        // user's answer, not the machine's. A spinner here
                        // would claim work that is not happening.
                        status = .done
                    } else {
                        status = .active
                    }
                } else {
                    status = .pending
                }
            } else {
                status = hasFinishedBootstrap ? .done : .pending
            }
            return StepProgress.Step(
                id: String(describing: bootstrapStep),
                title: bootstrapStep.title,
                status: status
            )
        }
    }

    // MARK: - Navigation between sheet steps

    public func goToAuthentication() {
        guard detailsAreValid else { return }
        step = .authentication
    }

    public func backToDetails() {
        step = .details
    }

    public func backToAuthentication() {
        cancelWork()
        step = .authentication
        failure = nil
        currentBootstrapStep = nil
        hasFinishedBootstrap = false
    }

    // MARK: - Key import

    public func importKey(at url: URL) {
        keyError = nil
        keyFileName = url.lastPathComponent

        // A file chosen through `fileImporter` in a sandboxed app arrives
        // security-scoped; without this the read fails with a permission error
        // that has nothing to do with the key.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let parsed = try OpenSSHKeyParser.parse(contentsOf: url)
            parsedKey = parsed
            keyDescription = AddServerModel.describe(parsed)
        } catch let error as ServerOSError {
            parsedKey = nil
            keyDescription = nil
            keyError = error
        } catch {
            parsedKey = nil
            keyDescription = nil
            keyError = ServerOSError.sshKeyUnusable(
                "ServerOS couldn't read \(url.lastPathComponent).",
                technical: "\(error)"
            )
        }
    }

    public func importFailed(_ error: Error) {
        parsedKey = nil
        keyDescription = nil
        keyError = ServerOSError.sshKeyUnusable(
            "ServerOS couldn't open that file.",
            technical: "\(error)"
        )
    }

    private static func describe(_ key: ParsedPrivateKey) -> String {
        switch key {
        case .ed25519: return "Ed25519 private key"
        case .p256: return "ECDSA P-256 private key"
        }
    }

    // MARK: - Running setup

    public func begin() {
        guard !isWorking else { return }
        failure = nil
        hasFinishedBootstrap = false
        step = .connecting
        isWorking = true
        currentBootstrapStep = .testingConnection

        work = Task { [weak self] in
            await self?.openConnection()
        }
    }

    /// Step one, on its own, so the host key can be put in front of a person
    /// *before* ServerOS installs anything.
    ///
    /// Honest caveat, recorded here rather than glossed over in the UI: SSH
    /// authenticates as part of the handshake, so by the time a fingerprint can
    /// be shown the credential has already been offered — exactly as with
    /// `ssh` itself on a first connection. What confirming here genuinely gates
    /// is everything that follows: the key install, the agent install, and the
    /// enrollment secret.
    private func openConnection() async {
        do {
            let authentication = try makeAuthentication()
            let connection = SSHClient(
                host: trimmedHost,
                port: port,
                username: trimmedUsername,
                authentication: authentication,
                pinnedHostKey: nil
            )
            try await connection.connect()

            client = connection
            observedFingerprint = await connection.observedHostKeyFingerprint
            isAwaitingHostKeyConfirmation = true
            isWorking = false
        } catch let error as ServerOSError {
            fail(with: error)
        } catch {
            fail(with: ServerOSError.sshFailed(
                "ServerOS couldn't connect to \(trimmedHost).",
                technical: "\(error)"
            ))
        }
    }

    public func confirmHostKey() {
        guard isAwaitingHostKeyConfirmation else { return }
        isAwaitingHostKeyConfirmation = false
        isWorking = true
        work = Task { [weak self] in
            await self?.runBootstrap()
        }
    }

    public func rejectHostKey() {
        isAwaitingHostKeyConfirmation = false
        cancelWork()
        failure = ServerOSError(
            code: "host_key_rejected",
            headline: "Setup stopped because you didn't recognise this server's fingerprint.",
            causes: [
                "Check the fingerprint against your hosting provider's console",
                "If it doesn't match, something else is answering on \(trimmedHost)",
            ],
            technical: observedFingerprint,
            isRetryable: true
        )
    }

    private func runBootstrap() async {
        guard let connection = client else {
            fail(with: ServerOSError.sshNotConnected)
            return
        }

        do {
            var installKey: ServerOSKeyPair?
            if willInstallOwnKey {
                installKey = try ServerOSKeyPair.generate(
                    comment: "serveros:\(AgentTokenMinter.defaultSubject())"
                )
            }

            let bootstrap = AgentBootstrap(
                client: connection,
                options: InstallOptions(),
                progress: makeProgressHandler()
            )
            let outcome = try await bootstrap.run(installKey: installKey)

            // The tunnel the app uses day to day opens its own connection, so
            // this one — and the thread its event loop owns — is closed here.
            await connection.disconnect()
            self.client = nil

            bootstrapResult = outcome
            setupSummary = ServerSetupSummary(
                serverID: outcome.serverID,
                osPretty: outcome.probe.prettyName ?? outcome.probe.systemName,
                architecture: outcome.probe.machine,
                kernel: outcome.probe.kernel,
                agentVersion: outcome.agentVersion ?? "unknown",
                hostKeyFingerprint: outcome.hostKeyFingerprint,
                installedOwnKey: outcome.generatedKeyPair != nil,
                warnings: outcome.warnings
            )
            currentBootstrapStep = nil
            hasFinishedBootstrap = true
            isWorking = false
            step = .done
        } catch let error as ServerOSError {
            fail(with: error)
        } catch {
            fail(with: ServerOSError.setupFailed(
                step: currentBootstrapStep?.title ?? BootstrapStep.installingAgent.title,
                reason: "Setting up \(trimmedHost) didn't finish.",
                technical: "\(error)"
            ))
        }
    }

    /// `AgentBootstrap` reports progress from its own actor, so every update
    /// hops back to the main actor before touching observable state.
    private func makeProgressHandler() -> @Sendable (BootstrapStep) -> Void {
        { [weak self] reported in
            Task { @MainActor in
                guard let self else { return }
                if reported == .done {
                    self.currentBootstrapStep = nil
                    self.hasFinishedBootstrap = true
                } else {
                    self.currentBootstrapStep = reported
                }
            }
        }
    }

    public func retry() {
        cancelWork()
        failure = nil
        observedFingerprint = nil
        isAwaitingHostKeyConfirmation = false
        hasFinishedBootstrap = false
        currentBootstrapStep = nil
        begin()
    }

    public func cancelWork() {
        work?.cancel()
        work = nil
        isWorking = false
        if let connection = client {
            client = nil
            Task { await connection.disconnect() }
        }
    }

    private func fail(with error: ServerOSError) {
        failure = error
        isWorking = false
        isAwaitingHostKeyConfirmation = false
    }

    private func makeAuthentication() throws -> SSHAuthentication {
        switch method {
        case .password:
            return .password(password)
        case .existingKey:
            guard let key = parsedKey else {
                throw ServerOSError.sshKeyUnusable(
                    "Choose a private key file before continuing.",
                    technical: nil
                )
            }
            return SSHAuthentication.privateKey(try key.nioPrivateKey())
        }
    }

    // MARK: - Handing the server over

    /// The two values the app needs to remember this server: one boring record
    /// for the local database, one secret bundle for the Keychain.
    public func finishedServer() -> (summary: ServerSummary, credential: ServerCredential)? {
        guard let result = bootstrapResult else { return nil }

        let summary = ServerSummary(
            id: result.serverID,
            name: trimmedName,
            hostname: trimmedHost,
            sshPort: port,
            sshUsername: trimmedUsername,
            agentPort: result.agentPort,
            osPretty: result.probe.prettyName,
            arch: result.probe.machine,
            lastSeenAt: Date(),
            addedAt: Date(),
            tags: [],
            sortIndex: 0,
            isDemo: false
        )

        let storedPassword: String? = (savesPassword || mustSavePassword) ? password : nil

        let credential = ServerCredential(
            serverID: result.serverID,
            agentSecret: result.agentSecret,
            agentPort: result.agentPort,
            sshPrivateKey: reusablePrivateKeySeed(from: result),
            sshPassword: storedPassword,
            hostKeyFingerprint: result.hostKeyFingerprint
        )

        return (summary, credential)
    }

    /// The key future connections will use. ServerOS's own key when it made one;
    /// otherwise the user's, but only if it is an Ed25519 seed — the one shape
    /// `ServerTunnel` can rebuild.
    private func reusablePrivateKeySeed(from result: BootstrapResult) -> Data? {
        if let generated = result.generatedKeyPair { return generated.privateKeySeed }
        if let key = parsedKey, case .ed25519(let seed) = key { return seed }
        return nil
    }
}

// MARK: - The sheet

/// Turning "I have a server" into "ServerOS manages this server".
public struct AddServerFlow: View {

    @Environment(\.dismiss) private var dismiss

    @State private var model = AddServerModel()
    @State private var isChoosingKeyFile = false

    private let onComplete: (ServerSummary, ServerCredential) -> Void

    public init(onComplete: @escaping (ServerSummary, ServerCredential) -> Void) {
        self.onComplete = onComplete
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Palette.divider)

            ScrollView {
                content
                    .padding(Spacing.screen)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider().overlay(Palette.divider)
            footer
        }
        .frame(width: 620, height: 520)
        .background(Palette.background)
        .fileImporter(
            isPresented: $isChoosingKeyFile,
            allowedContentTypes: [UTType.data]
        ) { (result: Result<URL, Error>) in
            // Explicitly typed: `fileImporter` has a single-selection and a
            // multiple-selection overload, and an un-annotated closure can
            // resolve to either.
            switch result {
            case .success(let url): model.importKey(at: url)
            case .failure(let error): model.importFailed(error)
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.hairline) {
            Text("Add a Server")
                .font(Typography.pageTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            Text("Step \(model.step.rawValue + 1) of \(AddServerModel.Step.allCases.count) · \(model.step.title)")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        switch model.step {
        case .details: detailsStep
        case .authentication: authenticationStep
        case .connecting: connectingStep
        case .done: doneStep
        }
    }

    // MARK: Details

    private var detailsStep: some View {
        VStack(alignment: .leading, spacing: Spacing.card) {
            Text("ServerOS connects over SSH once to install its agent, then talks to the agent from then on.")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            LabelledField(
                label: "Name",
                help: "What you'll call this server in ServerOS.",
                error: model.nameError
            ) {
                TextField("Production", text: $model.name)
                    .textFieldStyle(.roundedBorder)
            }

            LabelledField(
                label: "Host",
                help: "A hostname or IP address.",
                error: model.hostError
            ) {
                TextField("203.0.113.10", text: $model.host)
                    .textFieldStyle(.roundedBorder)
            }

            HStack(alignment: .top, spacing: Spacing.card) {
                LabelledField(
                    label: "SSH port",
                    help: "22 unless you've changed it.",
                    error: model.portError
                ) {
                    TextField("22", text: $model.portText)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 110)
                }

                LabelledField(
                    label: "Username",
                    help: "The account ServerOS logs in as. It needs root, or sudo without a password.",
                    error: model.usernameError
                ) {
                    TextField("root", text: $model.username)
                        .textFieldStyle(.roundedBorder)
                }
            }
        }
    }

    // MARK: Authentication

    private var authenticationStep: some View {
        VStack(alignment: .leading, spacing: Spacing.card) {
            Picker("How should ServerOS sign in?", selection: $model.method) {
                ForEach(AddServerModel.AuthenticationMethod.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityLabel("Authentication method")

            switch model.method {
            case .password:
                passwordFields
            case .existingKey:
                keyFields
            }

            Divider().overlay(Palette.divider)

            ownKeySection
        }
    }

    private var passwordFields: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            LabelledField(
                label: "Password",
                help: "Used once, to install the agent.",
                error: nil
            ) {
                SecureField("Password for \(model.trimmedUsername.isEmpty ? "this account" : model.trimmedUsername)", text: $model.password)
                    .textFieldStyle(.roundedBorder)
            }

            Toggle("Save this password in my Keychain", isOn: savePasswordBinding)
                .font(Typography.secondary)
                .disabled(model.mustSavePassword)

            if model.mustSavePassword {
                InlineBanner(
                    .warning,
                    "Without a key of its own, ServerOS needs this password to reconnect, so it has to be saved. Letting it create a key is the safer choice."
                )
            }
        }
    }

    private var keyFields: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            HStack(spacing: Spacing.element) {
                Button("Choose Key File…") { isChoosingKeyFile = true }
                    .buttonStyle(.secondary)

                if let fileName = model.keyFileName {
                    Text(fileName)
                        .font(Typography.code)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 0)
            }

            if let description = model.keyDescription {
                InlineBanner(.success, "ServerOS read a \(description).")
            }

            if let error = model.keyError {
                VStack(alignment: .leading, spacing: Spacing.tight) {
                    InlineBanner(.error, error.headline)
                    ForEach(error.causes, id: \.self) { cause in
                        Text("• \(cause)")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            Text("ServerOS reads Ed25519 and ECDSA P-256 keys without a passphrase. Passphrase-protected and RSA keys aren't supported — letting ServerOS create its own key is the way around both.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var ownKeySection: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            Toggle("Let ServerOS create its own key for this server", isOn: ownKeyBinding)
                .font(Typography.body.weight(.medium))
                .disabled(model.mustInstallOwnKey)

            Text("Recommended. ServerOS adds one dedicated line to this account's authorized_keys, uses it for every future connection, and never stores your password — and you can revoke it by deleting that one line.")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            if model.mustInstallOwnKey {
                InlineBanner(
                    .info,
                    "ServerOS can reuse an Ed25519 key but not an ECDSA one, so it will create its own key for this server."
                )
            }
        }
    }

    // MARK: Connecting

    @ViewBuilder
    private var connectingStep: some View {
        VStack(alignment: .leading, spacing: Spacing.card) {
            StepProgress(steps: model.progressSteps())

            if model.isAwaitingHostKeyConfirmation {
                hostKeyConfirmation
            }

            if let failure = model.failure {
                ErrorState(error: failure, retry: { model.retry() })
            }
        }
    }

    private var hostKeyConfirmation: some View {
        Card(
            title: "Is this the right server?",
            systemImage: "lock.shield"
        ) {
            VStack(alignment: .leading, spacing: Spacing.element) {
                Text("ServerOS has never connected to \(model.trimmedHost) before. This fingerprint identifies the machine that answered.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)

                Text(model.observedFingerprint ?? "No fingerprint was recorded.")
                    .font(Typography.code)
                    .foregroundStyle(Palette.textPrimary)
                    .textSelection(.enabled)
                    .padding(Spacing.element)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        Palette.surfaceElevated,
                        in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                    )
                    .accessibilityLabel("Host key fingerprint")
                    .accessibilityValue(model.observedFingerprint ?? "Not recorded")

                Text("Compare it against your hosting provider's console. Confirming pins this key: if it ever changes, ServerOS stops connecting instead of warning you and carrying on. Nothing is installed until you confirm.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: Spacing.element) {
                    Spacer(minLength: 0)
                    Button("I Don't Recognise It") { model.rejectHostKey() }
                        .buttonStyle(.secondary)
                    Button("Confirm and Continue") { model.confirmHostKey() }
                        .buttonStyle(.primary)
                }
            }
        }
    }

    // MARK: Done

    @ViewBuilder
    private var doneStep: some View {
        if let summary = model.setupSummary {
            VStack(alignment: .leading, spacing: Spacing.card) {
                HStack(spacing: Spacing.element) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 20))
                        .foregroundStyle(Palette.healthy)
                        .accessibilityHidden(true)
                    Text("\(model.trimmedName) is set up.")
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textPrimary)
                        .accessibilityAddTraits(.isHeader)
                }

                Card(title: "This Server") {
                    VStack(alignment: .leading, spacing: 0) {
                        KeyValueRow("Operating system", summary.osPretty)
                        KeyValueRow("Architecture", summary.architecture, monospaced: true)
                        KeyValueRow("Kernel", summary.kernel.isEmpty ? "Not reported" : summary.kernel, monospaced: true)
                        KeyValueRow("Agent", summary.agentVersion, monospaced: true)
                        KeyValueRow("Server ID", summary.serverID, monospaced: true, selectable: true)
                        KeyValueRow("Host key", summary.hostKeyFingerprint, monospaced: true, selectable: true)
                    }
                }

                Card(title: "What ServerOS Can Manage Here") {
                    VStack(alignment: .leading, spacing: Spacing.snug) {
                        Text("Health, processes, files and logs work on every Linux server. ServerOS asks the agent what else this machine has — Docker, systemd services, PostgreSQL — the first time it connects, and shows only the sections it can actually use.")
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)

                        if summary.installedOwnKey {
                            Text("ServerOS installed its own key in this account's authorized_keys. Your password was not saved.")
                                .font(Typography.metadata)
                                .foregroundStyle(Palette.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                ForEach(summary.warnings, id: \.self) { warning in
                    InlineBanner(.warning, warning)
                }
            }
        } else {
            // Reachable only if the result went missing between steps, which
            // would be a bug — say so rather than showing a blank pane.
            ErrorState(
                error: ServerOSError(
                    code: "setup_result_missing",
                    headline: "Setup finished but ServerOS lost track of the result.",
                    causes: ["Run setup for this server again."],
                    technical: nil,
                    isRetryable: true
                ),
                retry: { model.retry() }
            )
        }
    }

    // MARK: - Footer

    @ViewBuilder
    private var footer: some View {
        HStack(spacing: Spacing.element) {
            if model.step == .authentication {
                Button("Back") { model.backToDetails() }
                    .buttonStyle(.secondary)
            }
            if model.step == .connecting && model.failure != nil {
                Button("Back") { model.backToAuthentication() }
                    .buttonStyle(.secondary)
            }

            Spacer(minLength: 0)

            if model.step == .connecting && model.isWorking {
                InlineProgress(model.currentBootstrapStep?.title ?? "Working…")
            }

            switch model.step {
            case .details:
                Button("Cancel") { cancel() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Continue") { model.goToAuthentication() }
                    .buttonStyle(.primary)
                    .disabled(!model.detailsAreValid)
                    .keyboardShortcut(.defaultAction)

            case .authentication:
                Button("Cancel") { cancel() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Set Up Server") { model.begin() }
                    .buttonStyle(.primary)
                    .disabled(!model.authenticationIsValid)
                    .keyboardShortcut(.defaultAction)

            case .connecting:
                Button("Cancel") { cancel() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)

            case .done:
                Button("Open Server") { complete() }
                    .buttonStyle(.primary)
                    .disabled(model.setupSummary == nil)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    // MARK: - Bindings

    /// Forced on when there is no key to fall back to, so the toggle reflects
    /// what will actually happen rather than what the user last chose.
    private var savePasswordBinding: Binding<Bool> {
        Binding(
            get: { model.savesPassword || model.mustSavePassword },
            set: { model.savesPassword = $0 }
        )
    }

    private var ownKeyBinding: Binding<Bool> {
        Binding(
            get: { model.willInstallOwnKey },
            set: { model.installsOwnKey = $0 }
        )
    }

    // MARK: - Actions

    private func cancel() {
        model.cancelWork()
        dismiss()
    }

    private func complete() {
        guard let finished = model.finishedServer() else { return }
        onComplete(finished.summary, finished.credential)
        dismiss()
    }
}

// MARK: - Field

/// A label, a control, a one-line explanation and — only when there is one — a
/// specific error. Generic errors ("Invalid input") are what this exists to
/// make impossible.
private struct LabelledField<Control: View>: View {
    let label: String
    let help: String
    let error: String?
    let control: Control

    init(label: String, help: String, error: String?, @ViewBuilder control: () -> Control) {
        self.label = label
        self.help = help
        self.error = error
        self.control = control()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text(label)
                .font(Typography.secondary.weight(.medium))
                .foregroundStyle(Palette.textPrimary)

            control
                .font(Typography.body)

            if let error {
                Text(error)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.critical)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(help)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label)
        .accessibilityHint(error ?? help)
    }
}

// MARK: - Previews

#Preview("Add Server — details") {
    AddServerFlow { _, _ in }
}
