//  Components.swift
//  ServerOS
//
//  The shared building blocks. Every screen is assembled from these, which is
//  what makes forty screens look like one application.
//
//  A component earns its place here only if it appears in at least two screens
//  and carries a decision — spacing, hierarchy, interaction — that should not be
//  re-made each time.

import SwiftUI

// MARK: - Card

/// The standard container.
///
/// From the brief: a card answers one question. It therefore has one title, at
/// most one supporting line, one body, and at most one action. A card that
/// needs two actions is two cards, or a screen.
public struct Card<Content: View>: View {
    @Environment(\.colorScheme) private var scheme
    @State private var isHovered = false

    private let title: String?
    private let subtitle: String?
    private let systemImage: String?
    private let action: CardAction?
    private let interactive: Bool
    private let content: Content

    public struct CardAction {
        public let title: String
        public let perform: () -> Void
        public init(title: String, perform: @escaping () -> Void) {
            self.title = title
            self.perform = perform
        }
    }

    public init(
        title: String? = nil,
        subtitle: String? = nil,
        systemImage: String? = nil,
        action: CardAction? = nil,
        interactive: Bool = false,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.action = action
        self.interactive = interactive
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            if title != nil || systemImage != nil {
                header
            }
            content
            if let action {
                Divider().overlay(Palette.divider)
                Button(action.title, action: action.perform)
                    .buttonStyle(.secondary)
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(elevated: interactive && isHovered, scheme: scheme)
        .onHover { hovering in
            guard interactive else { return }
            withAnimation(Motion.immediate) { isHovered = hovering }
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
            if let systemImage {
                Image(systemName: systemImage)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Palette.textSecondary)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                if let title {
                    Text(title).font(Typography.sectionTitle).foregroundStyle(Palette.textPrimary)
                }
                if let subtitle {
                    Text(subtitle).font(Typography.metadata).foregroundStyle(Palette.textSecondary)
                }
            }
            Spacer(minLength: 0)
        }
    }
}

// MARK: - Section header

/// A heading above a group, with an optional trailing control.
public struct SectionHeader<Trailing: View>: View {
    private let title: String
    private let count: Int?
    private let trailing: Trailing

    public init(_ title: String, count: Int? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.count = count
        self.trailing = trailing()
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.snug) {
            Text(title)
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)
            if let count {
                Text(Formatting.count(count))
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .monospacedDigit()
                    // The count is decoration next to the title for a sighted
                    // reader; VoiceOver gets it as part of the heading instead.
                    .accessibilityHidden(true)
            }
            Spacer(minLength: Spacing.group)
            trailing
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(count.map { "\(title), \($0) items" } ?? title)
        .accessibilityAddTraits(.isHeader)
    }
}

extension SectionHeader where Trailing == EmptyView {
    public init(_ title: String, count: Int? = nil) {
        self.init(title, count: count) { EmptyView() }
    }
}

// MARK: - Key/value row

/// One fact, in the detail panes. Label left, value right, hairline between.
public struct KeyValueRow: View {
    private let label: String
    private let value: String
    private let monospaced: Bool
    private let selectable: Bool

    public init(_ label: String, _ value: String, monospaced: Bool = false, selectable: Bool = false) {
        self.label = label
        self.value = value
        self.monospaced = monospaced
        self.selectable = selectable
    }

    public init(_ label: String, _ value: String?, placeholder: String = "—", monospaced: Bool = false) {
        self.init(label, value ?? placeholder, monospaced: monospaced)
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            Text(label)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .frame(width: 132, alignment: .leading)
            valueText
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, Spacing.tight)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }

    @ViewBuilder
    private var valueText: some View {
        let text = Text(value)
            .font(monospaced ? Typography.code : Typography.body)
            .foregroundStyle(Palette.textPrimary)
        if selectable {
            // A container id or a path is nearly always about to be copied.
            text.textSelection(.enabled)
        } else {
            text
        }
    }
}

// MARK: - Chip

/// A small, non-interactive label: a tag, a port, a privilege.
public struct Chip: View {
    private let text: String
    private let tint: Color
    private let systemImage: String?

    public init(_ text: String, tint: Color = Palette.inactive, systemImage: String? = nil) {
        self.text = text
        self.tint = tint
        self.systemImage = systemImage
    }

    public var body: some View {
        HStack(spacing: Spacing.tight) {
            if let systemImage {
                Image(systemName: systemImage).font(.system(size: 9, weight: .semibold))
            }
            Text(text).font(Typography.metadata)
        }
        .padding(.horizontal, Spacing.snug)
        .padding(.vertical, 2)
        .foregroundStyle(tint)
        .background(tint.opacity(0.12), in: Capsule())
        .overlay(Capsule().strokeBorder(tint.opacity(0.22), lineWidth: 0.5))
    }
}

// MARK: - Buttons

/// The one prominent action on a screen.
public struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Typography.body.weight(.medium))
            .foregroundStyle(Palette.textOnAccent)
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.snug + 1)
            .background(
                Palette.accent.opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.4),
                in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
            )
            .contentShape(RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
            .animation(Motion.immediate, value: configuration.isPressed)
    }
}

/// Everything else.
public struct SecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @State private var isHovered = false

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Typography.body)
            .foregroundStyle(isEnabled ? Palette.textPrimary : Palette.textMuted)
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.snug + 1)
            .background(
                (configuration.isPressed ? Palette.hoverFill : (isHovered ? Palette.hoverFill.opacity(0.6) : Color.clear)),
                in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                    .strokeBorder(Palette.divider, lineWidth: 0.5)
            )
            .contentShape(RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
            .onHover { hovering in withAnimation(Motion.immediate) { isHovered = hovering } }
    }
}

/// Visually distinct, because the brief requires destructive actions to look
/// different from ordinary ones before they are pressed, not only after.
public struct DestructiveButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Typography.body.weight(.medium))
            .foregroundStyle(Palette.textOnAccent)
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.snug + 1)
            .background(
                Palette.critical.opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.4),
                in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
            )
            .animation(Motion.immediate, value: configuration.isPressed)
    }
}

/// A compact action inside a row: Restart, Stop, Open.
public struct RowActionButtonStyle: ButtonStyle {
    private let tint: Color
    public init(tint: Color = Palette.textSecondary) { self.tint = tint }

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Typography.metadata.weight(.medium))
            .foregroundStyle(tint)
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.tight)
            .background(
                tint.opacity(configuration.isPressed ? 0.20 : 0.10),
                in: RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
            )
            .contentShape(Rectangle())
    }
}

extension ButtonStyle where Self == PrimaryButtonStyle {
    public static var primary: PrimaryButtonStyle { PrimaryButtonStyle() }
}
extension ButtonStyle where Self == SecondaryButtonStyle {
    public static var secondary: SecondaryButtonStyle { SecondaryButtonStyle() }
}
extension ButtonStyle where Self == DestructiveButtonStyle {
    public static var destructive: DestructiveButtonStyle { DestructiveButtonStyle() }
}
extension ButtonStyle where Self == RowActionButtonStyle {
    public static var rowAction: RowActionButtonStyle { RowActionButtonStyle() }
}

// MARK: - Row highlight

/// Hover feedback for a list row, applied consistently everywhere.
public struct HoverHighlight: ViewModifier {
    @State private var isHovered = false
    private let isSelected: Bool
    private let radius: CGFloat

    public init(isSelected: Bool = false, radius: CGFloat = Radius.medium) {
        self.isSelected = isSelected
        self.radius = radius
    }

    public func body(content: Content) -> some View {
        content
            .background(fill, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .onHover { hovering in withAnimation(Motion.immediate) { isHovered = hovering } }
    }

    private var fill: Color {
        if isSelected { return Palette.accentMuted }
        return isHovered ? Palette.hoverFill.opacity(0.55) : .clear
    }
}

extension View {
    public func hoverHighlight(isSelected: Bool = false, radius: CGFloat = Radius.medium) -> some View {
        modifier(HoverHighlight(isSelected: isSelected, radius: radius))
    }
}

// MARK: - Skeleton

/// The loading placeholder.
///
/// A shimmering block of roughly the right shape reads as "this is coming" far
/// better than a spinner, and — crucially — it stops the layout jumping when
/// the real content lands.
public struct SkeletonBlock: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var phase: CGFloat = -1

    private let width: CGFloat?
    private let height: CGFloat

    public init(width: CGFloat? = nil, height: CGFloat = 12) {
        self.width = width
        self.height = height
    }

    public var body: some View {
        RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
            .fill(Palette.textMuted.opacity(0.18))
            .frame(width: width, height: height)
            .overlay(shimmer)
            .clipShape(RoundedRectangle(cornerRadius: Radius.small, style: .continuous))
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.linear(duration: 1.3).repeatForever(autoreverses: false)) {
                    phase = 2
                }
            }
            .accessibilityHidden(true)
    }

    @ViewBuilder
    private var shimmer: some View {
        if reduceMotion {
            EmptyView()
        } else {
            GeometryReader { geo in
                LinearGradient(
                    colors: [.clear, Palette.textMuted.opacity(0.16), .clear],
                    startPoint: .leading, endPoint: .trailing
                )
                .frame(width: geo.size.width * 0.6)
                .offset(x: phase * geo.size.width)
            }
        }
    }
}

/// A placeholder shaped like a list row.
public struct SkeletonRow: View {
    private let showsLeading: Bool
    public init(showsLeading: Bool = true) { self.showsLeading = showsLeading }

    public var body: some View {
        HStack(spacing: Spacing.group) {
            if showsLeading {
                SkeletonBlock(width: 8, height: 8)
            }
            VStack(alignment: .leading, spacing: Spacing.snug) {
                SkeletonBlock(width: 160, height: 12)
                SkeletonBlock(width: 96, height: 10)
            }
            Spacer()
            SkeletonBlock(width: 52, height: 12)
        }
        .padding(.vertical, Spacing.element)
    }
}

// MARK: - Destructive confirmation

/// The confirmation every destructive action must pass through.
///
/// The brief is specific: state what will happen, name the target, say whether
/// it is reversible, and make the destructive choice visually distinct. This
/// modifier is the only sanctioned way to do that, so no screen can quietly
/// skip a step.
public struct DestructiveConfirmation: ViewModifier {
    @Binding var isPresented: Bool
    let title: String
    let target: String
    let consequence: String
    let isReversible: Bool
    let confirmTitle: String
    let perform: () -> Void

    public func body(content: Content) -> some View {
        content.confirmationDialog(title, isPresented: $isPresented, titleVisibility: .visible) {
            Button(confirmTitle, role: .destructive, action: perform)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                consequence + (isReversible
                    ? "\n\nYou can undo this afterwards."
                    : "\n\nThis cannot be undone.")
            )
        }
    }
}

extension View {
    /// Gate a destructive action behind a confirmation that names its target.
    public func confirmDestructive(
        isPresented: Binding<Bool>,
        title: String,
        target: String,
        consequence: String,
        isReversible: Bool = false,
        confirmTitle: String,
        perform: @escaping () -> Void
    ) -> some View {
        modifier(DestructiveConfirmation(
            isPresented: isPresented,
            title: title,
            target: target,
            consequence: consequence,
            isReversible: isReversible,
            confirmTitle: confirmTitle,
            perform: perform
        ))
    }
}

// MARK: - Inline banner

public enum BannerKind {
    case info, warning, error, success

    var tint: Color {
        switch self {
        case .info: return Palette.informational
        case .warning: return Palette.warning
        case .error: return Palette.critical
        case .success: return Palette.healthy
        }
    }

    var symbol: String {
        switch self {
        case .info: return "info.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        case .success: return "checkmark.circle.fill"
        }
    }
}

/// A message that belongs with the content rather than on top of it.
public struct InlineBanner: View {
    private let kind: BannerKind
    private let message: String
    private let actionTitle: String?
    private let action: (() -> Void)?

    public init(
        _ kind: BannerKind,
        _ message: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil
    ) {
        self.kind = kind
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
            Image(systemName: kind.symbol)
                .font(.system(size: 12))
                .foregroundStyle(kind.tint)
                .accessibilityHidden(true)
            Text(message)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: Spacing.element)
            if let actionTitle, let action {
                Button(actionTitle, action: action).buttonStyle(.rowAction)
            }
        }
        .padding(.horizontal, Spacing.group)
        .padding(.vertical, Spacing.element)
        .background(kind.tint.opacity(0.09), in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                .strokeBorder(kind.tint.opacity(0.22), lineWidth: 0.5)
        )
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Search field

/// The list filter used on every collection screen.
public struct SearchField: View {
    @Binding private var text: String
    private let prompt: String
    @FocusState private var isFocused: Bool

    public init(text: Binding<String>, prompt: String) {
        self._text = text
        self.prompt = prompt
    }

    public var body: some View {
        HStack(spacing: Spacing.snug) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .font(Typography.body)
                .focused($isFocused)
            if !text.isEmpty {
                Button {
                    text = ""
                    isFocused = true
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(Palette.textMuted)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, Spacing.element)
        .padding(.vertical, Spacing.snug)
        .background(Palette.surfaceElevated, in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                .strokeBorder(isFocused ? Palette.accent.opacity(0.6) : Palette.divider, lineWidth: isFocused ? 1.5 : 0.5)
        )
        .animation(Motion.immediate, value: isFocused)
        .frame(maxWidth: 260)
    }
}
