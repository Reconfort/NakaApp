//  HealthViews.swift
//  ServerOS
//
//  How state is shown.
//
//  The rule the whole product hangs on: **never communicate state through
//  colour alone.** Every view here pairs a colour with a shape, a word and,
//  where there is room, an explanation. That is not only an accessibility
//  requirement — it is what makes a glance at the dashboard actually informative
//  rather than merely colourful.

import SwiftUI

// MARK: - Status dot

/// The smallest unit of state: a filled glyph whose *shape* differs per state.
///
/// A circle, a triangle and an octagon are distinguishable at 8pt without any
/// colour at all, which is the point.
public struct StatusDot: View {
    private let state: HealthState
    private let size: CGFloat
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(_ state: HealthState, size: CGFloat = 10) {
        self.state = state
        self.size = size
    }

    public var body: some View {
        Image(systemName: state.symbolName)
            .font(.system(size: size, weight: .semibold))
            .foregroundStyle(Palette.color(for: state))
            .symbolRenderingMode(.hierarchical)
            // A state change is worth noticing; a fade is enough to catch the
            // eye without being a performance.
            .animation(Motion.honouring(reduceMotion, Motion.status), value: state)
            .accessibilityLabel(state.accessibilityLabel)
    }
}

/// Dot plus word — used wherever there is room for both.
public struct HealthBadge: View {
    private let state: HealthState
    private let compact: Bool

    public init(_ state: HealthState, compact: Bool = false) {
        self.state = state
        self.compact = compact
    }

    public var body: some View {
        HStack(spacing: Spacing.snug) {
            StatusDot(state, size: compact ? 9 : 11)
            Text(state.label)
                .font(compact ? Typography.metadata : Typography.body.weight(.medium))
                .foregroundStyle(Palette.color(for: state))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(state.accessibilityLabel)
    }
}

// MARK: - The health card

/// The card at the top of the Overview and of every server.
///
/// It answers, in order: what state is this in, what does that mean, and what
/// can I do about it. Metrics come *below* that, because a number without a
/// verdict is work the user has to do themselves.
public struct HealthCard: View {
    @Environment(\.colorScheme) private var scheme

    private let title: String
    private let health: ServerHealth
    private let metrics: Metrics?
    private let onAction: ((HealthAction) -> Void)?

    public init(
        title: String,
        health: ServerHealth,
        metrics: Metrics? = nil,
        onAction: ((HealthAction) -> Void)? = nil
    ) {
        self.title = title
        self.health = health
        self.metrics = metrics
        self.onAction = onAction
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            HStack(alignment: .top, spacing: Spacing.group) {
                VStack(alignment: .leading, spacing: Spacing.snug) {
                    Text(title)
                        .font(Typography.pageTitle)
                        .foregroundStyle(Palette.textPrimary)
                    HealthBadge(health.state)
                }
                Spacer(minLength: Spacing.group)
                if let action = health.action.title, let onAction {
                    Button(action) { onAction(health.action) }
                        .buttonStyle(health.state >= .critical ? AnyButtonStyle(.destructive) : AnyButtonStyle(.secondary))
                }
            }

            VStack(alignment: .leading, spacing: Spacing.tight) {
                Text(health.summary)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                if let reason = health.reason {
                    Text(reason)
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let metrics {
                Divider().overlay(Palette.divider)
                MetricStrip(metrics: metrics)
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(scheme: scheme)
        .overlay(alignment: .leading) {
            // A thin state-coloured edge. Redundant with the badge on purpose:
            // it lets someone scanning a column of cards find the bad one
            // without reading any of them.
            RoundedRectangle(cornerRadius: 2, style: .continuous)
                .fill(Palette.color(for: health.state))
                .frame(width: 3)
                .padding(.vertical, Spacing.card)
                .accessibilityHidden(true)
        }
    }
}

/// A type-erased button style, so a card can pick its style at runtime.
public struct AnyButtonStyle: ButtonStyle {
    private let makeBodyClosure: (Configuration) -> AnyView

    public init<S: ButtonStyle>(_ style: S) {
        makeBodyClosure = { configuration in
            AnyView(style.makeBody(configuration: configuration))
        }
    }

    public func makeBody(configuration: Configuration) -> some View {
        makeBodyClosure(configuration)
    }
}

// MARK: - Metric strip

/// CPU / Memory / Storage in a row. The supporting detail under a verdict.
public struct MetricStrip: View {
    private let metrics: Metrics

    public init(metrics: Metrics) { self.metrics = metrics }

    public var body: some View {
        HStack(alignment: .top, spacing: Spacing.section) {
            MetricTile(
                label: "CPU",
                value: metrics.isWarmingUp ? nil : metrics.cpu.usagePercent,
                caption: "\(metrics.cpu.coreCount) core\(metrics.cpu.coreCount == 1 ? "" : "s")"
            )
            MetricTile(
                label: "Memory",
                value: metrics.memory.usagePercent,
                caption: Formatting.usage(used: metrics.memory.usedBytes, total: metrics.memory.totalBytes)
            )
            MetricTile(
                label: "Storage",
                value: metrics.disk.usagePercent,
                caption: Formatting.usage(used: metrics.disk.usedBytes, total: metrics.disk.totalBytes)
            )
            Spacer(minLength: 0)
        }
    }
}

/// One labelled number with a usage bar under it.
public struct MetricTile: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let label: String
    /// Nil means "not known yet" — shown as a placeholder, never as 0%.
    private let value: Double?
    private let caption: String?

    public init(label: String, value: Double?, caption: String? = nil) {
        self.label = label
        self.value = value
        self.caption = caption
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text(label)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .textCase(.uppercase)
                .tracking(0.4)

            Text(value.map { Formatting.percent($0) } ?? "—")
                .font(Typography.metric)
                .foregroundStyle(value == nil ? Palette.textMuted : Palette.textPrimary)
                .contentTransition(.numericText())
                .animation(Motion.honouring(reduceMotion, Motion.value), value: value)

            UsageBar(fraction: value.map { $0 / 100 })
                .frame(width: 92)

            if let caption {
                Text(caption)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value.map { "\(Int($0.rounded())) percent\(caption.map { ", \($0)" } ?? "")" } ?? "Not available yet")
    }
}

// MARK: - Usage bar

/// A thin proportion bar whose colour crosses into warning and critical at the
/// same thresholds the health evaluator uses — so the bar and the verdict can
/// never disagree.
public struct UsageBar: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let fraction: Double?
    private let height: CGFloat

    public init(fraction: Double?, height: CGFloat = 4) {
        self.fraction = fraction
        self.height = height
    }

    public var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Palette.textMuted.opacity(0.18))
                if let fraction {
                    Capsule()
                        .fill(tint)
                        .frame(width: max(2, geo.size.width * clamped(fraction)))
                        .animation(Motion.honouring(reduceMotion, Motion.value), value: fraction)
                }
            }
        }
        .frame(height: height)
        .accessibilityHidden(true)
    }

    private func clamped(_ v: Double) -> Double { min(max(v, 0), 1) }

    private var tint: Color {
        guard let fraction else { return Palette.inactive }
        let percent = fraction * 100
        if percent >= HealthThresholds.diskCriticalPercent { return Palette.critical }
        if percent >= HealthThresholds.diskWarningPercent { return Palette.warning }
        return Palette.accent
    }
}

// MARK: - Sparkline

/// A short history of one value, drawn as a filled line.
///
/// Deliberately tiny and axis-free: it answers "is this climbing?" and nothing
/// else. A real chart belongs on the metrics detail screen, not in a row.
public struct Sparkline: View {
    private let values: [Double]
    private let tint: Color

    public init(values: [Double], tint: Color = Palette.accent) {
        self.values = values
        self.tint = tint
    }

    public var body: some View {
        GeometryReader { geo in
            let points = normalisedPoints(in: geo.size)
            ZStack {
                if points.count >= 2 {
                    Path { path in
                        path.move(to: CGPoint(x: points[0].x, y: geo.size.height))
                        for p in points { path.addLine(to: p) }
                        path.addLine(to: CGPoint(x: points[points.count - 1].x, y: geo.size.height))
                        path.closeSubpath()
                    }
                    .fill(LinearGradient(
                        colors: [tint.opacity(0.28), tint.opacity(0.02)],
                        startPoint: .top, endPoint: .bottom
                    ))

                    Path { path in
                        path.move(to: points[0])
                        for p in points.dropFirst() { path.addLine(to: p) }
                    }
                    .stroke(tint, style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
                }
            }
        }
        .accessibilityHidden(true)
    }

    private func normalisedPoints(in size: CGSize) -> [CGPoint] {
        guard values.count >= 2 else { return [] }
        let lower = values.min() ?? 0
        let upper = values.max() ?? 1
        // A flat line should sit in the middle rather than pinned to an edge,
        // which is what a zero-range normalisation would produce.
        let range = upper - lower
        let step = size.width / CGFloat(values.count - 1)
        return values.enumerated().map { index, value in
            let normalised: CGFloat = range <= 0.0001 ? 0.5 : CGFloat((value - lower) / range)
            return CGPoint(x: CGFloat(index) * step, y: size.height * (1 - normalised))
        }
    }
}

// MARK: - Running / stopped pill

/// State for things that are simply on or off: containers, services.
public struct RunPill: View {
    public enum RunState {
        case running, stopped, paused, restarting, failed, unknown

        var label: String {
            switch self {
            case .running: return "Running"
            case .stopped: return "Stopped"
            case .paused: return "Paused"
            case .restarting: return "Restarting"
            case .failed: return "Failed"
            case .unknown: return "Unknown"
            }
        }

        var tint: Color {
            switch self {
            case .running: return Palette.healthy
            case .stopped, .unknown: return Palette.inactive
            case .paused: return Palette.informational
            case .restarting: return Palette.warning
            case .failed: return Palette.critical
            }
        }

        var symbol: String {
            switch self {
            case .running: return "circle.fill"
            case .stopped: return "stop.fill"
            case .paused: return "pause.fill"
            case .restarting: return "arrow.triangle.2.circlepath"
            case .failed: return "exclamationmark.triangle.fill"
            case .unknown: return "questionmark"
            }
        }

        /// Map a Docker container state string.
        public static func fromContainer(_ state: String) -> RunState {
            switch state {
            case "running": return .running
            case "paused": return .paused
            case "restarting": return .restarting
            case "dead": return .failed
            case "exited", "created": return .stopped
            default: return .unknown
            }
        }

        /// Map the agent's rolled-up service state.
        public static func fromService(_ state: String) -> RunState {
            switch state {
            case "running": return .running
            case "stopped": return .stopped
            case "failed": return .failed
            case "starting", "stopping": return .restarting
            default: return .unknown
            }
        }
    }

    private let state: RunState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(_ state: RunState) { self.state = state }

    public var body: some View {
        HStack(spacing: Spacing.tight) {
            Image(systemName: state.symbol)
                .font(.system(size: 7, weight: .bold))
            Text(state.label)
                .font(Typography.metadata.weight(.medium))
        }
        .foregroundStyle(state.tint)
        .padding(.horizontal, Spacing.snug)
        .padding(.vertical, 2)
        .background(state.tint.opacity(0.12), in: Capsule())
        .animation(Motion.honouring(reduceMotion, Motion.status), value: state.label)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(state.label)
    }
}
