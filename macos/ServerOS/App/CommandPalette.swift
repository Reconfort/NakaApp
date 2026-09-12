//  CommandPalette.swift
//  ServerOS
//
//  ⌘K.
//
//  The signature interaction. It is not a search box over a static menu — it is
//  built from live state, so "Restart estatify-api" is offered exactly when
//  that container exists, on the server you are looking at. Navigation and
//  actions are in one list because from the user's side they are one gesture:
//  "the thing I want, now".

import SwiftUI

public struct CommandPalette: View {
    @Binding var isPresented: Bool
    let items: [PaletteItem]
    let onSelect: (PaletteItem) -> Void

    @State private var query = ""
    @State private var highlighted = 0
    @FocusState private var isFieldFocused: Bool

    private let maxVisible = 9

    public init(isPresented: Binding<Bool>, items: [PaletteItem], onSelect: @escaping (PaletteItem) -> Void) {
        self._isPresented = isPresented
        self.items = items
        self.onSelect = onSelect
    }

    private var results: [PaletteItem] {
        Array(FuzzyMatch.rank(items, query: query).prefix(40))
    }

    public var body: some View {
        ZStack(alignment: .top) {
            // A scrim, not a blur: the content behind stays legible so the
            // palette feels like a layer on the app rather than a modal wall.
            Color.black.opacity(0.18)
                .ignoresSafeArea()
                .onTapGesture { isPresented = false }

            panel
                .padding(.top, 96)
        }
        .onExitCommand { isPresented = false }
    }

    private var panel: some View {
        VStack(spacing: 0) {
            field
            if !results.isEmpty {
                Divider().overlay(Palette.divider)
                list
            } else if !query.isEmpty {
                noResults
            }
        }
        .frame(width: 560)
        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: Radius.sheet, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.sheet, style: .continuous)
                .strokeBorder(Palette.divider, lineWidth: 0.5)
        )
        .shadow(Elevation.floating(.dark))
        .onAppear { isFieldFocused = true }
    }

    private var field: some View {
        HStack(spacing: Spacing.group) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 14))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)

            TextField("Search or run a command", text: $query)
                .textFieldStyle(.plain)
                .font(.system(size: 16))
                .focused($isFieldFocused)
                .onSubmit(activateHighlighted)
                .onChange(of: query) { _, _ in highlighted = 0 }

            if !results.isEmpty {
                Text("↑↓ to move · ↩ to run")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .accessibilityHidden(true)
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.group)
        // Arrow keys move the highlight without leaving the text field, which
        // is what makes a palette feel like a palette rather than a form.
        .background {
            VStack {
                Button("") { move(-1) }.keyboardShortcut(.upArrow, modifiers: [])
                Button("") { move(1) }.keyboardShortcut(.downArrow, modifiers: [])
            }
            .opacity(0)
            .accessibilityHidden(true)
        }
    }

    private var list: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 1) {
                    ForEach(Array(results.enumerated()), id: \.element.id) { index, item in
                        PaletteRow(item: item, isHighlighted: index == highlighted)
                            .id(item.id)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                highlighted = index
                                activateHighlighted()
                            }
                            .onHover { hovering in
                                if hovering { highlighted = index }
                            }
                    }
                }
                .padding(Spacing.snug)
            }
            .frame(maxHeight: CGFloat(maxVisible) * 44)
            .onChange(of: highlighted) { _, new in
                guard results.indices.contains(new) else { return }
                withAnimation(Motion.immediate) {
                    proxy.scrollTo(results[new].id, anchor: .center)
                }
            }
        }
    }

    private var noResults: some View {
        VStack(spacing: Spacing.snug) {
            Text("Nothing matches “\(query)”")
                .font(Typography.body)
                .foregroundStyle(Palette.textSecondary)
            Text("Try a server name, a container, or an action like “restart”.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity)
    }

    private func move(_ delta: Int) {
        guard !results.isEmpty else { return }
        // Wrap, because reaching the end and being stuck is annoying.
        highlighted = (highlighted + delta + results.count) % results.count
    }

    private func activateHighlighted() {
        guard results.indices.contains(highlighted) else { return }
        onSelect(results[highlighted])
    }
}

private struct PaletteRow: View {
    let item: PaletteItem
    let isHighlighted: Bool

    var body: some View {
        HStack(spacing: Spacing.group) {
            Image(systemName: item.kind.symbol)
                .font(.system(size: 12))
                .frame(width: 20)
                .foregroundStyle(isHighlighted ? Palette.accent : Palette.textMuted)

            VStack(alignment: .leading, spacing: 1) {
                Text(item.title)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                if let subtitle = item.subtitle {
                    Text(subtitle)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: Spacing.element)

            Text(item.kind.label)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        }
        .padding(.horizontal, Spacing.group)
        .padding(.vertical, Spacing.element)
        .background(
            isHighlighted ? Palette.accentMuted : Color.clear,
            in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.kind.label): \(item.title)")
        .accessibilityAddTraits(isHighlighted ? [.isSelected, .isButton] : .isButton)
    }
}
