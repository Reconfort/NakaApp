//  StateViews.swift
//  ServerOS
//
//  The states that are not "here is your data".
//
//  From the brief: every feature must account for loading, empty, offline,
//  permission-denied, error and success. Those are not edge cases to be bolted
//  on — for a tool that talks to remote infrastructure over a tunnel, they are
//  most of what the user actually sees on a bad day, and a bad day is exactly
//  when the product has to be good.
//
//  `ScreenState` exists so a screen declares all of them in one place and
//  cannot quietly omit one.

import SwiftUI

// MARK: - Screen state

/// What a data-backed screen is currently showing.
public enum ScreenState<Value> {
    /// First load, nothing to show yet.
    case loading
    /// Loaded, with content.
    case loaded(Value)
    /// Loaded, but there is genuinely nothing.
    case empty
    /// Failed.
    case failed(ServerOSError)
    /// The server does not offer this capability at all.
    case unavailable(subsystem: String, reason: String)

    public var value: Value? {
        if case .loaded(let v) = self { return v }
        return nil
    }

    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }
}

/// Renders a `ScreenState`, so no screen has to remember the full set.
public struct StatefulContent<Value, Content: View, EmptyContent: View>: View {
    private let state: ScreenState<Value>
    private let retry: (() -> Void)?
    private let content: (Value) -> Content
    private let emptyContent: () -> EmptyContent

    public init(
        _ state: ScreenState<Value>,
        retry: (() -> Void)? = nil,
        @ViewBuilder content: @escaping (Value) -> Content,
        @ViewBuilder empty: @escaping () -> EmptyContent
    ) {
        self.state = state
        self.retry = retry
        self.content = content
        self.emptyContent = empty
    }

    public var body: some View {
        switch state {
        case .loading:
            LoadingList()
        case .loaded(let value):
            content(value)
        case .empty:
            emptyContent()
        case .failed(let error):
            ErrorState(error: error, retry: retry)
        case .unavailable(let subsystem, let reason):
            UnavailableState(subsystem: subsystem, reason: reason)
        }
    }
}

// MARK: - Empty state

/// "There is nothing here, and here is what to do about it."
///
/// Never "No data." Every empty state names the thing that is missing, says why
/// it matters, and offers the action that fills it.
public struct EmptyState: View {
    private let systemImage: String
    private let title: String
    private let message: String
    private let actionTitle: String?
    private let action: (() -> Void)?
    private let secondaryActionTitle: String?
    private let secondaryAction: (() -> Void)?

    public init(
        systemImage: String,
        title: String,
        message: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil,
        secondaryActionTitle: String? = nil,
        secondaryAction: (() -> Void)? = nil
    ) {
        self.systemImage = systemImage
        self.title = title
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
        self.secondaryActionTitle = secondaryActionTitle
        self.secondaryAction = secondaryAction
    }

    public var body: some View {
        VStack(spacing: Spacing.group) {
            Image(systemName: systemImage)
                .font(.system(size: 32, weight: .light))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)

            VStack(spacing: Spacing.snug) {
                Text(title)
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                Text(message)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 340)
            }

            if actionTitle != nil || secondaryActionTitle != nil {
                HStack(spacing: Spacing.element) {
                    if let actionTitle, let action {
                        Button(actionTitle, action: action).buttonStyle(.primary)
                    }
                    if let secondaryActionTitle, let secondaryAction {
                        Button(secondaryActionTitle, action: secondaryAction).buttonStyle(.secondary)
                    }
                }
                .padding(.top, Spacing.tight)
            }
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Error state

/// A failure, explained.
///
/// Headline, then the usual causes, then a retry, then — and only then, behind
/// a disclosure — the technical detail an engineer needs. The raw error is
/// never hidden, but it is never the first thing either.
public struct ErrorState: View {
    private let error: ServerOSError
    private let retry: (() -> Void)?
    @State private var showTechnical = false

    public init(error: ServerOSError, retry: (() -> Void)? = nil) {
        self.error = error
        self.retry = retry
    }

    public var body: some View {
        VStack(spacing: Spacing.group) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(Palette.warning)
                .accessibilityHidden(true)

            VStack(spacing: Spacing.element) {
                Text(error.headline)
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)

                if !error.causes.isEmpty {
                    VStack(alignment: .leading, spacing: Spacing.tight) {
                        ForEach(error.causes, id: \.self) { cause in
                            HStack(alignment: .firstTextBaseline, spacing: Spacing.snug) {
                                Text("•").foregroundStyle(Palette.textMuted)
                                Text(cause)
                                    .font(Typography.secondary)
                                    .foregroundStyle(Palette.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .frame(maxWidth: 380, alignment: .leading)
                }
            }

            HStack(spacing: Spacing.element) {
                if let retry, error.isRetryable {
                    Button("Try Again", action: retry).buttonStyle(.primary)
                }
                if error.technical != nil {
                    Button(showTechnical ? "Hide Technical Details" : "Technical Details") {
                        withAnimation(Motion.appear) { showTechnical.toggle() }
                    }
                    .buttonStyle(.secondary)
                }
            }

            if showTechnical {
                ScrollView {
                    // The build goes here rather than in the error itself:
                    // `technical` is what went wrong, this is which copy of
                    // ServerOS it went wrong in. A screenshot of this panel
                    // identifies its own binary, which is worth a great deal
                    // when the fix is already written but not yet running.
                    Text([error.technical, "(\(ServerOSError.buildStamp))"]
                            .compactMap { $0 }
                            .joined(separator: "\n\n"))
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textSecondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Spacing.element)
                }
                .frame(maxWidth: 420, maxHeight: 140)
                .background(Palette.surfaceElevated, in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                        .strokeBorder(Palette.divider, lineWidth: 0.5)
                )
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Unavailable capability

/// This server simply does not have the thing.
///
/// Distinct from an error on purpose: nothing is broken, and offering "Try
/// Again" would be a lie. A server without Docker will not grow Docker by
/// being asked twice.
public struct UnavailableState: View {
    private let subsystem: String
    private let reason: String

    public init(subsystem: String, reason: String) {
        self.subsystem = subsystem
        self.reason = reason
    }

    public var body: some View {
        VStack(spacing: Spacing.group) {
            Image(systemName: "minus.circle")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)
            VStack(spacing: Spacing.snug) {
                Text("\(subsystem) isn't available on this server")
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                Text(reason)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Loading

/// The skeleton shown while a list loads.
public struct LoadingList: View {
    private let rows: Int
    public init(rows: Int = 6) { self.rows = rows }

    public var body: some View {
        VStack(spacing: 0) {
            ForEach(0..<rows, id: \.self) { _ in
                SkeletonRow()
                Divider().overlay(Palette.divider)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .accessibilityLabel("Loading")
    }
}

/// A small inline spinner with a label, for actions in progress.
public struct InlineProgress: View {
    private let label: String
    public init(_ label: String) { self.label = label }

    public var body: some View {
        HStack(spacing: Spacing.element) {
            ProgressView().controlSize(.small)
            Text(label)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(label)
    }
}

// MARK: - Connection progress

/// The multi-step progress shown while a server connects or is set up.
///
/// Showing the steps rather than a bare spinner matters here: connecting
/// involves SSH, an agent install and an enrolment, and when it fails the user
/// needs to know *which* of those failed.
public struct StepProgress: View {
    public struct Step: Identifiable, Equatable {
        public enum Status: Equatable { case pending, active, done, failed }
        public let id: String
        public let title: String
        public var status: Status

        public init(id: String, title: String, status: Status = .pending) {
            self.id = id
            self.title = title
            self.status = status
        }
    }

    private let steps: [Step]
    public init(steps: [Step]) { self.steps = steps }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            ForEach(steps) { step in
                HStack(spacing: Spacing.element) {
                    glyph(for: step.status)
                        .frame(width: 16, height: 16)
                    Text(step.title)
                        .font(Typography.body)
                        .foregroundStyle(colour(for: step.status))
                    Spacer(minLength: 0)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(step.title), \(describe(step.status))")
            }
        }
    }

    @ViewBuilder
    private func glyph(for status: Step.Status) -> some View {
        switch status {
        case .pending:
            Image(systemName: "circle")
                .font(.system(size: 11))
                .foregroundStyle(Palette.textMuted)
        case .active:
            ProgressView().controlSize(.small)
        case .done:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Palette.healthy)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Palette.critical)
        }
    }

    private func colour(for status: Step.Status) -> Color {
        switch status {
        case .pending: return Palette.textMuted
        case .active: return Palette.textPrimary
        case .done: return Palette.textSecondary
        case .failed: return Palette.critical
        }
    }

    private func describe(_ status: Step.Status) -> String {
        switch status {
        case .pending: return "waiting"
        case .active: return "in progress"
        case .done: return "done"
        case .failed: return "failed"
        }
    }
}

// MARK: - Offline banner

/// Shown at the top of a server's screens while it is unreachable, so stale
/// data on screen is never mistaken for live data.
public struct StaleDataBanner: View {
    private let lastUpdated: Date?
    private let onReconnect: () -> Void

    public init(lastUpdated: Date?, onReconnect: @escaping () -> Void) {
        self.lastUpdated = lastUpdated
        self.onReconnect = onReconnect
    }

    public var body: some View {
        InlineBanner(
            .warning,
            lastUpdated.map { "Showing data from \(Formatting.relative($0)). ServerOS can't reach this server." }
                ?? "ServerOS can't reach this server.",
            actionTitle: "Reconnect",
            action: onReconnect
        )
    }
}
