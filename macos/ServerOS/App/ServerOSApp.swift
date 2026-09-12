//  ServerOSApp.swift
//  ServerOS
//
//  The entry point and the menu bar.
//
//  Menu commands matter more here than in most apps: the brief asks for a
//  keyboard-first Mac experience, and a command that exists only as a button in
//  a toolbar is not discoverable, not scriptable by a power user, and not
//  reachable by anyone driving the app from the keyboard.

import SwiftData
import SwiftUI

@main
struct ServerOSApp: App {
    @State private var model: AppModel
    @State private var startupError: String?

    init() {
        // A failure here means the local database could not be opened at all.
        // Falling back to an in-memory store keeps the app usable — the user can
        // still connect to servers this session — and the banner tells them what
        // they have lost, which beats a launch crash.
        do {
            _model = State(initialValue: try AppModel.makeDefault())
        } catch {
            let container = try? ServerStore.makeContainer(inMemory: true)
            _model = State(initialValue: AppModel(
                store: ServerStore(container: container ?? ServerStore.emptyContainer())
            ))
            _startupError = State(initialValue:
                "ServerOS couldn't open its saved server list, so this session starts empty. "
                + "Your servers are still set up — reopening the app usually restores them.")
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .frame(
                    minWidth: Layout.windowMinWidth,
                    minHeight: Layout.windowMinHeight
                )
                .overlay(alignment: .top) {
                    if let startupError {
                        InlineBanner(.warning, startupError, actionTitle: "Dismiss") {
                            self.startupError = nil
                        }
                        .padding(Spacing.card)
                        .transition(.move(edge: .top).combined(with: .opacity))
                    }
                }
        }
        .defaultSize(width: 1180, height: 760)
        .commands { ServerOSCommands() }

        Settings {
            SettingsScreen()
                .environment(model)
                .frame(width: 560, height: 420)
        }
    }
}

// MARK: - Menu bar

struct ServerOSCommands: Commands {
    @FocusedValue(\.navigation) private var navigation
    @FocusedValue(\.commandPaletteTrigger) private var showPalette
    @FocusedValue(\.addServerTrigger) private var addServer

    var body: some Commands {
        // Replace "New Window" with the action people actually want from ⌘N.
        CommandGroup(replacing: .newItem) {
            Button("Add Server…") { addServer?() }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(addServer == nil)
        }

        CommandMenu("Go") {
            Button("Command Palette…") { showPalette?() }
                .keyboardShortcut("k", modifiers: .command)
                .disabled(showPalette == nil)

            Divider()

            // ⌘1…⌘4 at the fleet level; inside a server the same keys move
            // between that server's sections, which is what the user means by
            // "the fourth thing in the sidebar" either way.
            ForEach(FleetSection.allCases, id: \.self) { section in
                Button(section.title) { navigation?.go(to: section.route) }
                    .keyboardShortcut(KeyEquivalent(section.keyboardShortcut), modifiers: .command)
                    .disabled(navigation == nil || navigation?.route.serverID != nil)
            }

            Divider()

            Button("Back") { navigation?.goBack() }
                .keyboardShortcut("[", modifiers: .command)
                .disabled(navigation?.canGoBack != true)

            Button("Leave Server") { navigation?.leaveServer() }
                .keyboardShortcut(.escape, modifiers: .command)
                .disabled(navigation?.route.serverID == nil)
        }

        CommandMenu("Server") {
            ForEach(ServerSection.allCases, id: \.self) { section in
                Button(section.title) { navigation?.select(section: section) }
                    .keyboardShortcut(
                        KeyEquivalent(section.keyboardShortcut ?? "1"),
                        modifiers: [.command, .shift]
                    )
                    .disabled(navigation?.route.serverID == nil)
            }
        }

        CommandGroup(after: .toolbar) {
            Button("Refresh") {
                NotificationCenter.default.post(name: .serverOSRefreshRequested, object: nil)
            }
            .keyboardShortcut("r", modifiers: .command)
        }

        CommandGroup(replacing: .help) {
            Link("ServerOS Documentation", destination: URL(string: "https://github.com/Reconfort/NakaApp")!)
        }
    }
}

extension Notification.Name {
    /// ⌘R. Broadcast rather than plumbed through focus values because every
    /// screen refreshes something different, and each one knows what.
    public static let serverOSRefreshRequested = Notification.Name("com.orionsystems.ServerOS.refresh")
}

extension ServerStore {
    /// Last-resort container so a launch failure never becomes a crash.
    static func emptyContainer() -> ModelContainer {
        // If even an in-memory container cannot be built, the SwiftData stack
        // is unusable and there is nothing sensible left to do.
        try! ServerStore.makeContainer(inMemory: true)
    }
}
