//  Theme.swift
//  ServerOS
//
//  The design system, in one file so it can be reviewed as a system.
//
//  The governing idea: **this application should feel expensive because it is
//  restrained.** Infrastructure data is already visually noisy — a hundred
//  containers, a thousand processes, four-digit percentages. If the chrome is
//  also loud, nothing reads. So:
//
//   * One accent colour, used sparingly, for product identity and selection.
//   * Four semantic colours that mean exactly one thing each and are never used
//     decoratively. Green is never "a nice green"; green means healthy.
//   * A neutral surface ladder built from macOS's own semantic colours, so the
//     app inherits the system's light and dark treatments — including increased
//     contrast and reduced transparency — rather than re-inventing them badly.
//   * Type does the hierarchy. There are seven roles and no others.
//
//  Anything not expressible with these tokens is a design question, not a
//  styling question, and should be settled before it is written.

import SwiftUI

// MARK: - Colour

public enum Palette {

    // --- Product identity ---------------------------------------------------

    /// The one accent. Used for selection, focus, primary actions and links —
    /// nowhere else. A deep indigo rather than the system blue so ServerOS is
    /// recognisably itself while still sitting comfortably beside native chrome.
    public static let accent = Color(
        light: Color(red: 0.35, green: 0.33, blue: 0.78),
        dark: Color(red: 0.55, green: 0.53, blue: 0.95)
    )

    /// A dimmer accent for hover states and low-emphasis fills.
    public static let accentMuted = Color(
        light: Color(red: 0.35, green: 0.33, blue: 0.78).opacity(0.12),
        dark: Color(red: 0.55, green: 0.53, blue: 0.95).opacity(0.18)
    )

    // --- Semantic status ----------------------------------------------------
    //
    // Deliberately desaturated compared with the system defaults. On a screen
    // that may show forty status dots at once, saturated greens and reds turn
    // into a Christmas tree and stop signalling anything.

    public static let healthy = Color(
        light: Color(red: 0.16, green: 0.55, blue: 0.32),
        dark: Color(red: 0.38, green: 0.78, blue: 0.52)
    )

    public static let warning = Color(
        light: Color(red: 0.72, green: 0.46, blue: 0.06),
        dark: Color(red: 0.96, green: 0.70, blue: 0.28)
    )

    public static let critical = Color(
        light: Color(red: 0.75, green: 0.22, blue: 0.20),
        dark: Color(red: 0.95, green: 0.45, blue: 0.42)
    )

    public static let informational = Color(
        light: Color(red: 0.15, green: 0.42, blue: 0.72),
        dark: Color(red: 0.45, green: 0.68, blue: 0.95)
    )

    /// Inactive, stopped, unknown — present but not asking for anything.
    public static let inactive = Color(
        light: Color(red: 0.53, green: 0.55, blue: 0.58),
        dark: Color(red: 0.56, green: 0.58, blue: 0.62)
    )

    // --- Surfaces -----------------------------------------------------------
    //
    // Built on the system's own semantics so Increase Contrast, Reduce
    // Transparency and both appearances are handled by AppKit rather than by us.

    /// The window's base.
    public static let background = Color(nsColor: .windowBackgroundColor)
    /// A card or grouped region sitting on the background.
    public static let surface = Color(nsColor: .controlBackgroundColor)
    /// A surface raised above another surface — a popover, an inner group.
    public static let surfaceElevated = Color(nsColor: .underPageBackgroundColor)
    /// Hairlines and dividers.
    public static let divider = Color(nsColor: .separatorColor)
    /// The subtle fill behind a hovered row.
    public static let hoverFill = Color(nsColor: .unemphasizedSelectedContentBackgroundColor)

    // --- Text ---------------------------------------------------------------

    public static let textPrimary = Color(nsColor: .labelColor)
    public static let textSecondary = Color(nsColor: .secondaryLabelColor)
    public static let textMuted = Color(nsColor: .tertiaryLabelColor)
    /// For text on top of an accent or semantic fill.
    public static let textOnAccent = Color.white

    /// The colour for a health state. The single place that mapping lives.
    public static func color(for state: HealthState) -> Color {
        switch state {
        case .healthy: return healthy
        case .warning: return warning
        case .critical: return critical
        case .offline: return inactive
        case .unknown: return inactive
        }
    }
}

extension Color {
    /// Build a colour that resolves differently in light and dark.
    ///
    /// `Color(light:dark:)` does not exist in SwiftUI, and an asset catalogue
    /// entry cannot be reviewed in a diff. A dynamic `NSColor` gives both.
    public init(light: Color, dark: Color) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(isDark ? dark : light)
        })
    }
}

// MARK: - Typography

/// Seven roles. Adding an eighth should require an argument.
///
/// Everything is built from the system font so the app inherits SF Pro's
/// optical sizing, and so a user who has changed their text size is respected.
public enum Typography {

    /// A server's name in its header. The only genuinely large text in the app.
    public static let display = Font.system(size: 26, weight: .semibold, design: .default)

    /// A screen title: "Docker", "Files", "Overview".
    public static let pageTitle = Font.system(size: 19, weight: .semibold, design: .default)

    /// A group heading inside a screen: "Containers", "Recent Activity".
    public static let sectionTitle = Font.system(size: 13, weight: .semibold, design: .default)

    /// A number the eye should land on: "23%", "4.2 GB".
    ///
    /// Monospaced digits so a value updating from 9% to 10% does not shift the
    /// layout, which is the difference between "alive" and "jittery".
    public static let metric = Font.system(size: 21, weight: .medium, design: .rounded)
        .monospacedDigit()

    /// A smaller metric inside a dense row.
    public static let metricSmall = Font.system(size: 14, weight: .medium).monospacedDigit()

    /// Ordinary running text and list rows.
    public static let body = Font.system(size: 13, weight: .regular)

    /// Supporting text under a value or title.
    public static let secondary = Font.system(size: 12, weight: .regular)

    /// Timestamps, counts, the least important thing on the row.
    public static let metadata = Font.system(size: 11, weight: .regular)

    /// Paths, log lines, commands, container ids.
    public static let code = Font.system(size: 12, weight: .regular, design: .monospaced)

    public static let codeSmall = Font.system(size: 11, weight: .regular, design: .monospaced)
}

// MARK: - Spacing

/// A 4-point grid, named by intent rather than by size, so a reader can tell
/// whether a gap is meaningful or incidental.
public enum Spacing {
    /// Between a glyph and its label.
    public static let hairline: CGFloat = 2
    /// Inside a compact control.
    public static let tight: CGFloat = 4
    /// Between tightly related lines of text.
    public static let snug: CGFloat = 6
    /// The default gap between elements in a group.
    public static let element: CGFloat = 8
    /// Between groups inside a card.
    public static let group: CGFloat = 12
    /// A card's internal padding.
    public static let card: CGFloat = 16
    /// Between cards.
    public static let between: CGFloat = 16
    /// A screen's outer padding.
    public static let screen: CGFloat = 20
    /// Between major sections of a screen.
    public static let section: CGFloat = 28
    /// Around an empty state, to let it breathe.
    public static let generous: CGFloat = 40
}

// MARK: - Shape

public enum Radius {
    /// Chips, small fills, progress bars.
    public static let small: CGFloat = 5
    /// Buttons, inner groups.
    public static let medium: CGFloat = 8
    /// Cards.
    public static let large: CGFloat = 12
    /// Sheets and large containers.
    public static let sheet: CGFloat = 16
}

public enum Elevation {
    /// A card at rest. Almost nothing — a hairline does most of the work.
    public static func resting(_ scheme: ColorScheme) -> ShadowStyle {
        ShadowStyle(color: .black.opacity(scheme == .dark ? 0.32 : 0.06), radius: 2, y: 1)
    }

    /// A card under the pointer.
    public static func hovered(_ scheme: ColorScheme) -> ShadowStyle {
        ShadowStyle(color: .black.opacity(scheme == .dark ? 0.42 : 0.10), radius: 6, y: 2)
    }

    /// A floating panel: command palette, popover.
    public static func floating(_ scheme: ColorScheme) -> ShadowStyle {
        ShadowStyle(color: .black.opacity(scheme == .dark ? 0.55 : 0.18), radius: 24, y: 8)
    }
}

public struct ShadowStyle: Equatable, Sendable {
    public let color: Color
    public let radius: CGFloat
    public let y: CGFloat

    public init(color: Color, radius: CGFloat, y: CGFloat) {
        self.color = color
        self.radius = radius
        self.y = y
    }
}

// MARK: - Motion

/// Durations and curves, named by what they communicate.
///
/// The rule from the brief: never animate to be lively. Animate to show that a
/// thing became another thing, or that something arrived. Everything here is
/// short enough to feel like feedback rather than performance.
public enum Motion {
    /// Hover, focus, selection — must feel instantaneous.
    public static let immediate = Animation.easeOut(duration: 0.12)
    /// A value changing: a percentage ticking up, a bar growing.
    public static let value = Animation.easeInOut(duration: 0.35)
    /// A status changing: stopped becoming running. Slightly slower, because
    /// the user should notice it happened.
    public static let status = Animation.spring(response: 0.4, dampingFraction: 0.8)
    /// Something appearing or leaving: a row, a card, a banner.
    public static let appear = Animation.spring(response: 0.32, dampingFraction: 0.86)
    /// A sheet or panel.
    public static let panel = Animation.spring(response: 0.38, dampingFraction: 0.9)

    /// Respect Reduce Motion: returns nil so `withAnimation(nil)` applies the
    /// change instantly.
    public static func honouring(_ reduceMotion: Bool, _ animation: Animation) -> Animation? {
        reduceMotion ? nil : animation
    }
}

// MARK: - Layout constants

public enum Layout {
    public static let sidebarMinWidth: CGFloat = 208
    public static let sidebarIdealWidth: CGFloat = 232
    public static let sidebarMaxWidth: CGFloat = 300
    public static let contentMinWidth: CGFloat = 620
    public static let windowMinWidth: CGFloat = 900
    public static let windowMinHeight: CGFloat = 620
    /// Cards stop growing past this so a wide window does not produce
    /// absurdly long lines of text.
    public static let readableMaxWidth: CGFloat = 1100
    public static let denseRowHeight: CGFloat = 28
    public static let comfortableRowHeight: CGFloat = 40
}

// MARK: - View helpers

extension View {
    /// The standard card treatment: surface fill, hairline, gentle corner.
    public func cardSurface(
        elevated: Bool = false,
        scheme: ColorScheme = .light,
        radius: CGFloat = Radius.large
    ) -> some View {
        let shadow = elevated ? Elevation.hovered(scheme) : Elevation.resting(scheme)
        return self
            .background(Palette.surface, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Palette.divider, lineWidth: 0.5)
            )
            .shadow(color: shadow.color, radius: shadow.radius, y: shadow.y)
    }

    /// Apply a shadow style.
    public func shadow(_ style: ShadowStyle) -> some View {
        shadow(color: style.color, radius: style.radius, y: style.y)
    }

    /// Constrain content to a readable width and centre it, which is what keeps
    /// a maximised window from looking like a spreadsheet.
    public func readableWidth(_ max: CGFloat = Layout.readableMaxWidth) -> some View {
        frame(maxWidth: max, alignment: .leading)
    }

    /// Standard screen padding.
    public func screenPadding() -> some View {
        padding(.horizontal, Spacing.screen).padding(.vertical, Spacing.card)
    }
}
