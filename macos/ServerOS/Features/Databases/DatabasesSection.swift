//  DatabasesSection.swift
//  ServerOS
//
//  PostgreSQL, as infrastructure rather than as a query tool.
//
//  The brief is explicit that this is **not** a SQL IDE, and resisting that is
//  the main design decision here. A psql prompt already exists and is better
//  than anything we would build; what does not exist is a calm answer to the
//  questions an operator actually has at 2am:
//
//    Is the database healthy? How close am I to running out of connections?
//    Is it serving from memory or from disk? Which table is about to become a
//    problem? Who is connected right now, and what are they waiting on?
//
//  So the screen is inventory and health: two pinned cards that give the verdict,
//  and four tables underneath that give the evidence.
//
//  Three decisions worth knowing about:
//
//  * **A failure to authenticate is not a generic error.** If the agent can see
//    a PostgreSQL instance but cannot sign in to it, the honest message names
//    the configuration file and the role, because "Request failed" would cost
//    the reader an afternoon.
//  * **Query text is withheld until it is asked for.** A running statement can
//    contain a customer's email address, and the request is recorded in the
//    server's own activity log. Both of those are said plainly before the toggle
//    does anything.
//  * **Sequential scans get a sentence, not just a number.** "seq_scan 412,000"
//    means nothing to most people; "this table is nearly always read without an
//    index" means everything, and it is the single most useful thing this screen
//    can tell someone.

import Combine
import SwiftUI

/// PostgreSQL on one server: health, statistics, and the four inventories.
public struct DatabasesSection: View {

    private let session: ServerSession
    private let navigation: NavigationModel

    @State private var overview: ScreenState<PostgresOverview> = .loading
    /// Everything the agent could find listening, whether or not it could log in.
    @State private var instances: [DatabaseInstance] = []
    @State private var tab: DatabaseTab = .databases

    @State private var databases: ScreenState<[PostgresDatabase]> = .loading
    @State private var tables: ScreenState<[PostgresTable]> = .loading
    @State private var connections: ScreenState<[PostgresConnection]> = .loading
    @State private var roles: ScreenState<[PostgresRole]> = .loading

    @State private var selectedDatabase: String?
    @State private var showsQueryText = false
    @State private var isExplainingQueryText = false
    @State private var reloadNonce = 0

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Palette.divider)
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task(id: overviewKey) { await loadOverview() }
        .task(id: loadKey) { await loadCurrentTab() }
        .onChange(of: session.capabilities) { _, _ in reloadNonce += 1 }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            reloadNonce += 1
        }
        // Not a destructive action, so not a destructive confirmation — but it
        // does reveal other people's data, so it is never a silent toggle.
        .confirmationDialog(
            "Show the SQL these connections are running?",
            isPresented: $isExplainingQueryText,
            titleVisibility: .visible
        ) {
            Button("Show Query Text") {
                showsQueryText = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Live SQL often contains real data — email addresses, order numbers, anything that was passed as a "
                 + "literal. ServerOS will ask \(session.name) for it, and that request is recorded in the server's "
                 + "activity log with your name on it.")
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Databases")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(countLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Spacer(minLength: Spacing.group)

            if let version = overview.value?.version {
                Chip("PostgreSQL \(version)", tint: Palette.inactive, systemImage: "cylinder.split.1x2")
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    private var countLine: String {
        guard session.capabilities.postgres else {
            return "No database server is managed on \(session.name)."
        }
        if let value = overview.value {
            let databases = value.databaseCount.map { "\(Formatting.count($0)) database\($0 == 1 ? "" : "s")" }
            let size = value.totalSizeBytes.map { Formatting.bytes($0) }
            return [databases, size].compactMap { $0 }.joined(separator: " · ")
        }
        return "Reading PostgreSQL on \(session.name)…"
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if !session.capabilities.postgres {
            UnavailableState(
                subsystem: "Databases",
                reason: "ServerOS didn't find a PostgreSQL server the agent can reach on \(session.name). "
                    + "A database running inside a container is managed from Docker instead."
            )
        } else {
            VStack(spacing: Spacing.between) {
                summaryCards
                inventory
            }
            .padding(.horizontal, Spacing.screen)
            .padding(.top, Spacing.group)
        }
    }

    // MARK: Pinned cards

    @ViewBuilder
    private var summaryCards: some View {
        if let failure = authenticationFailure {
            // The realistic failure, and the one a generic error handles worst.
            InlineBanner(
                .warning,
                "ServerOS can see PostgreSQL on \(session.name)\(instanceDescription), but the agent couldn't sign "
                    + "in. It connects as the role named under \"postgres\" in /etc/serveros/agent.json — by default "
                    + "serveros, over the socket in /var/run/postgresql. Create that role and grant it pg_monitor, "
                    + "or point the agent at one that exists. (\(failure.headline))",
                actionTitle: "Try Again",
                action: { reloadNonce += 1 }
            )
        } else {
            StatefulContent(overview, retry: { reloadNonce += 1 }) { value in
                HStack(alignment: .top, spacing: Spacing.between) {
                    overviewCard(value)
                    statisticsCard(value)
                }
            } empty: {
                EmptyState(
                    systemImage: "cylinder.split.1x2",
                    title: "PostgreSQL returned nothing",
                    message: "The agent connected but got no server statistics back.",
                    actionTitle: "Try Again",
                    action: { reloadNonce += 1 }
                )
            }
        }
    }

    /// What state is it in, and how close is it to its connection ceiling?
    private func overviewCard(_ value: PostgresOverview) -> some View {
        Card(title: "PostgreSQL", systemImage: "cylinder.split.1x2") {
            VStack(alignment: .leading, spacing: Spacing.group) {
                HealthBadge(DatabasesSection.healthState(value.health))

                Text(value.healthReason ?? DatabasesSection.healthSummary(value.health))
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                connectionUsage(value)

                VStack(alignment: .leading, spacing: 0) {
                    KeyValueRow("Version", value.version, placeholder: "Unknown")
                    KeyValueRow("Uptime", value.uptimeSeconds.map { Formatting.duration(seconds: $0) }, placeholder: "Unknown")
                    KeyValueRow("Data directory", value.dataDirectory, placeholder: "Unknown", monospaced: true)
                }
            }
        }
    }

    private func connectionUsage(_ value: PostgresOverview) -> some View {
        let current = value.currentConnections
        let maximum = value.maxConnections
        let fraction: Double? = {
            if let percent = value.connectionUsagePercent { return percent / 100 }
            guard let current, let maximum, maximum > 0 else { return nil }
            return Double(current) / Double(maximum)
        }()

        return VStack(alignment: .leading, spacing: Spacing.tight) {
            HStack(alignment: .firstTextBaseline) {
                Text("Connections")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                Spacer(minLength: Spacing.element)
                Text(DatabasesSection.connectionsLabel(current: current, maximum: maximum))
                    .font(Typography.metricSmall)
                    .foregroundStyle(Palette.textPrimary)
            }
            UsageBar(fraction: fraction)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Connections")
        .accessibilityValue(DatabasesSection.connectionsLabel(current: current, maximum: maximum))
    }

    /// Is it serving from memory, and is it rolling back work it should not be?
    private func statisticsCard(_ value: PostgresOverview) -> some View {
        Card(title: "Statistics", systemImage: "chart.bar") {
            VStack(alignment: .leading, spacing: Spacing.group) {
                cacheHitRatio(value)
                transactionCounts(value)
                deadlocks(value)
            }
        }
    }

    private func cacheHitRatio(_ value: PostgresOverview) -> some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text("Cache hit ratio")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .textCase(.uppercase)
                .tracking(0.4)

            Text(value.cacheHitRatio.map { Formatting.percent($0) } ?? "—")
                .font(Typography.metric)
                .foregroundStyle(cacheTint(value.cacheHitRatio))

            // The number is meaningless without this sentence, and the sentence
            // is the reason the number is on the screen at all.
            Text(cacheAdvice(value.cacheHitRatio))
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Cache hit ratio")
        .accessibilityValue(value.cacheHitRatio.map { Formatting.percent($0) } ?? "Unknown")
    }

    private func transactionCounts(_ value: PostgresOverview) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("Committed", value.transactionsCommitted.map { Formatting.count($0) }, placeholder: "Unknown")
            KeyValueRow("Rolled back", DatabasesSection.rollbackLabel(value), placeholder: "Unknown")
        }
    }

    @ViewBuilder
    private func deadlocks(_ value: PostgresOverview) -> some View {
        if let count = value.deadlocks, count > 0 {
            InlineBanner(
                .warning,
                "\(Formatting.count(count)) deadlock\(count == 1 ? "" : "s") since this server started. "
                    + "Two transactions each waited for a lock the other held, and PostgreSQL killed one of them."
            )
        } else {
            HStack(spacing: Spacing.snug) {
                StatusDot(.healthy, size: 9)
                Text("No deadlocks since startup.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }
            .accessibilityElement(children: .combine)
        }
    }

    // MARK: Inventory

    private var inventory: some View {
        VStack(spacing: 0) {
            HStack(spacing: Spacing.group) {
                Picker("", selection: $tab) {
                    ForEach(DatabaseTab.allCases, id: \.self) { option in
                        Text(option.title).tag(option)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 420)
                .accessibilityLabel("Inventory")

                Spacer(minLength: Spacing.element)

                if tab == .connections {
                    queryTextToggle
                }
            }
            .padding(.bottom, Spacing.group)

            tabContent
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    private var queryTextToggle: some View {
        Button(showsQueryText ? "Hide Query Text" : "Show Query Text") {
            if showsQueryText {
                showsQueryText = false
            } else {
                isExplainingQueryText = true
            }
        }
        .buttonStyle(.secondary)
        .help(showsQueryText
              ? "Stop asking the server for running statements"
              : "Live SQL can contain customer data, and the request is logged")
    }

    @ViewBuilder
    private var tabContent: some View {
        switch tab {
        case .databases: databasesTable
        case .tables: tablesTable
        case .connections: connectionsTable
        case .roles: rolesTable
        }
    }

    // MARK: Databases table

    private var databasesTable: some View {
        StatefulContent(databases, retry: { reloadNonce += 1 }) { rows in
            VStack(spacing: 0) {
                Table(rows, selection: $selectedDatabase) {
                    TableColumn("Database") { row in
                        HStack(spacing: Spacing.snug) {
                            Text(row.name)
                                .font(Typography.body)
                                .foregroundStyle(Palette.textPrimary)
                                .lineLimit(1)
                            if row.isTemplate == true {
                                // A template is not a database anyone uses; say
                                // so rather than letting someone wonder why it
                                // is empty.
                                Chip("Template", tint: Palette.inactive)
                            }
                        }
                    }
                    .width(min: 140, ideal: 200)

                    TableColumn("Owner") { row in
                        Text(row.owner ?? "Unknown")
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 90, ideal: 120)

                    TableColumn("Size") { row in
                        Text(Formatting.bytes(row.sizeBytes))
                            .font(Typography.metricSmall)
                            .foregroundStyle(Palette.textPrimary)
                            .accessibilityLabel("Size")
                            .accessibilityValue(Formatting.bytes(row.sizeBytes))
                    }
                    .width(min: 80, ideal: 100)

                    TableColumn("Tables") { row in
                        Text(row.tableCount.map { Formatting.count($0) } ?? "—")
                            .font(Typography.metricSmall)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 60, ideal: 76, max: 110)

                    TableColumn("Encoding") { row in
                        Text(row.encoding ?? "—")
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 70, ideal: 86, max: 120)

                    TableColumn("Collation") { row in
                        Text(row.collation ?? "—")
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                            .lineLimit(1)
                    }
                    .width(min: 90, ideal: 120, max: 180)

                    TableColumn("Connections") { row in
                        Text(DatabasesSection.connectionLimit(row.connectionLimit))
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 90, ideal: 110, max: 140)
                }
                .tableStyle(.inset)

                databaseSelectionBar
            }
        } empty: {
            EmptyState(
                systemImage: "cylinder.split.1x2",
                title: "No databases",
                message: "This PostgreSQL server has no databases beyond its own templates."
            )
        }
    }

    @ViewBuilder
    private var databaseSelectionBar: some View {
        if let selected = selectedDatabase {
            HStack(spacing: Spacing.element) {
                Text("Selected \(selected).")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                Spacer(minLength: Spacing.element)
                Button("Show Tables in \(selected)") { tab = .tables }
                    .buttonStyle(.rowAction)
            }
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.element)
        }
    }

    // MARK: Tables table

    private var tablesTable: some View {
        StatefulContent(tables, retry: { reloadNonce += 1 }) { rows in
            VStack(spacing: 0) {
                scanAdvice(rows)

                Table(rows) {
                    TableColumn("Table") { row in
                        VStack(alignment: .leading, spacing: 0) {
                            Text(row.name)
                                .font(Typography.body)
                                .foregroundStyle(Palette.textPrimary)
                                .lineLimit(1)
                            Text(row.schema)
                                .font(Typography.metadata)
                                .foregroundStyle(Palette.textMuted)
                        }
                        .padding(.vertical, 2)
                    }
                    .width(min: 140, ideal: 200)

                    TableColumn("Rows") { row in
                        Text(row.rowsEstimate.map { Formatting.count($0) } ?? "—")
                            .font(Typography.metricSmall)
                            .foregroundStyle(Palette.textPrimary)
                            .accessibilityLabel("Estimated rows")
                            .accessibilityValue(row.rowsEstimate.map { Formatting.count($0) } ?? "Unknown")
                    }
                    .width(min: 80, ideal: 100)

                    TableColumn("Total size") { row in
                        Text(Formatting.bytes(row.totalSizeBytes))
                            .font(Typography.metricSmall)
                            .foregroundStyle(Palette.textPrimary)
                    }
                    .width(min: 80, ideal: 100)

                    // "Data" rather than "Table": a column headed Table next to
                    // the column of table names reads as a mistake.
                    TableColumn("Data") { row in
                        Text(Formatting.bytes(row.tableSizeBytes))
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 70, ideal: 90)

                    TableColumn("Indexes") { row in
                        Text(Formatting.bytes(row.indexSizeBytes))
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                    }
                    .width(min: 70, ideal: 90)

                    TableColumn("Scans") { row in
                        scansCell(row)
                    }
                    .width(min: 130, ideal: 170, max: 230)

                    TableColumn("Last vacuum") { row in
                        Text(DatabasesSection.timeDescription(row.lastVacuum))
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                            .lineLimit(1)
                    }
                    .width(min: 90, ideal: 120, max: 170)

                    TableColumn("Last analyze") { row in
                        Text(DatabasesSection.timeDescription(row.lastAnalyze))
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                            .lineLimit(1)
                    }
                    .width(min: 90, ideal: 120, max: 170)
                }
                .tableStyle(.inset)
            }
        } empty: {
            EmptyState(
                systemImage: "tablecells",
                title: selectedDatabase.map { "No tables in \($0)" } ?? "No tables",
                message: "PostgreSQL reported no user tables here. System catalogues are not shown."
            )
        }
    }

    private func scansCell(_ row: PostgresTable) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(DatabasesSection.scanCount(row.seqScans)) seq · \(DatabasesSection.scanCount(row.indexScans)) index")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .lineLimit(1)
            if DatabasesSection.isSeqScanHeavy(row) {
                Chip("Mostly sequential", tint: Palette.warning, systemImage: "exclamationmark.triangle.fill")
            }
        }
        .padding(.vertical, 2)
        .help("Sequential scans read the whole table; index scans jump straight to the rows.")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Scans")
        .accessibilityValue(
            "\(DatabasesSection.scanCount(row.seqScans)) sequential, \(DatabasesSection.scanCount(row.indexScans)) by index"
                + (DatabasesSection.isSeqScanHeavy(row) ? ", mostly sequential" : "")
        )
    }

    /// The one piece of genuine advice this screen can offer.
    @ViewBuilder
    private func scanAdvice(_ rows: [PostgresTable]) -> some View {
        let heavy = rows.filter { DatabasesSection.isSeqScanHeavy($0) }
        if !heavy.isEmpty {
            InlineBanner(
                .info,
                "\(Formatting.list(heavy.map(\.name))) \(heavy.count == 1 ? "is" : "are") read mostly by sequential "
                    + "scan — PostgreSQL walks every row rather than using an index. On a large table that is usually "
                    + "a missing index on whatever the query filters by."
            )
            .padding(.bottom, Spacing.element)
        }
    }

    // MARK: Connections table

    private var connectionsTable: some View {
        StatefulContent(connections, retry: { reloadNonce += 1 }) { rows in
            Table(rows) {
                TableColumn("PID") { row in
                    Text(String(row.pid))
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 56, ideal: 66, max: 90)

                TableColumn("User") { row in
                    VStack(alignment: .leading, spacing: 0) {
                        Text(row.user ?? "—")
                            .font(Typography.body)
                            .foregroundStyle(Palette.textPrimary)
                            .lineLimit(1)
                        Text(row.clientAddr ?? "local socket")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                            .lineLimit(1)
                    }
                    .padding(.vertical, 2)
                }
                .width(min: 110, ideal: 150)

                TableColumn("Database") { row in
                    Text(row.database ?? "—")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                }
                .width(min: 90, ideal: 120)

                TableColumn("Application") { row in
                    Text(DatabasesSection.applicationName(row.applicationName))
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                }
                .width(min: 100, ideal: 140)

                TableColumn("State") { row in
                    Chip(
                        DatabasesSection.connectionState(row.state),
                        tint: DatabasesSection.connectionStateTint(row.state)
                    )
                }
                .width(min: 80, ideal: 100, max: 130)

                TableColumn("In state") { row in
                    Text(DatabasesSection.elapsed(since: row.stateChange))
                        .font(Typography.metricSmall)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 70, ideal: 84, max: 110)

                TableColumn("Waiting on") { row in
                    Text(row.waitEventType ?? "Nothing")
                        .font(Typography.secondary)
                        .foregroundStyle(row.waitEventType == nil ? Palette.textMuted : Palette.textSecondary)
                        .lineLimit(1)
                }
                .width(min: 80, ideal: 110, max: 150)

                TableColumn("Backend") { row in
                    Text(row.backendType ?? "—")
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                }
                .width(min: 90, ideal: 120, max: 170)

                TableColumn("Query") { row in
                    queryCell(row)
                }
                .width(min: 120, ideal: 220)
            }
            .tableStyle(.inset)
        } empty: {
            EmptyState(
                systemImage: "point.3.connected.trianglepath.dotted",
                title: "No connections",
                message: "Nothing is connected to this PostgreSQL server right now, not even a background worker — "
                    + "which is unusual enough to be worth a look."
            )
        }
    }

    @ViewBuilder
    private func queryCell(_ row: PostgresConnection) -> some View {
        if let preview = row.queryPreview, !preview.isEmpty {
            Text(preview)
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textSecondary)
                .lineLimit(1)
                .truncationMode(.tail)
                .textSelection(.enabled)
                .help(preview)
        } else if showsQueryText {
            Text("None")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        } else {
            // The column stays in place whether or not text is revealed, so the
            // table does not reflow when the toggle is used — and so the
            // withholding is visible rather than invisible.
            Text("Hidden")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .accessibilityLabel("Query text hidden")
        }
    }

    // MARK: Roles table

    private var rolesTable: some View {
        StatefulContent(roles, retry: { reloadNonce += 1 }) { rows in
            Table(rows) {
                TableColumn("Role") { row in
                    Text(row.name)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                }
                .width(min: 110, ideal: 160)

                TableColumn("Privileges") { row in
                    privilegeCell(row)
                }
                .width(min: 180, ideal: 300)

                TableColumn("Connections") { row in
                    Text(row.hasUnlimitedConnections
                         ? "Unlimited"
                         : Formatting.count(row.connectionLimit ?? 0))
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 90, ideal: 110, max: 140)

                TableColumn("Valid until") { row in
                    Text(DatabasesSection.timeDescription(row.validUntil, whenMissing: "No expiry"))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                }
                .width(min: 100, ideal: 130, max: 180)
            }
            .tableStyle(.inset)
        } empty: {
            EmptyState(
                systemImage: "person.badge.key",
                title: "No roles",
                message: "PostgreSQL returned no roles, which should not happen — every server has at least one."
            )
        }
    }

    @ViewBuilder
    private func privilegeCell(_ row: PostgresRole) -> some View {
        if row.privileges.isEmpty {
            Text("Can log in, nothing else")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        } else {
            HStack(spacing: Spacing.tight) {
                ForEach(row.privileges, id: \.self) { privilege in
                    Chip(privilege, tint: DatabasesSection.privilegeTint(privilege))
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Privileges: \(row.privileges.joined(separator: ", "))")
        }
    }

    // MARK: - Loading

    private struct LoadKey: Equatable {
        var tab: DatabaseTab
        var database: String?
        var includeQueryText: Bool
        var nonce: Int
    }

    private var loadKey: LoadKey {
        LoadKey(
            tab: tab,
            // The selected database only changes what the Tables tab asks for,
            // and query text only the Connections tab — folding them in
            // unconditionally would re-fetch three inventories every time
            // someone clicked a row.
            database: tab == .tables ? selectedDatabase : nil,
            includeQueryText: tab == .connections ? showsQueryText : false,
            nonce: reloadNonce
        )
    }

    private var overviewKey: Int { reloadNonce }

    private var authenticationFailure: ServerOSError? {
        guard case .failed(let error) = overview else { return nil }
        // Only a *found but unreachable* instance earns the specific message.
        // If the agent found nothing at all, the generic failure is the truth.
        return instances.isEmpty ? nil : error
    }

    private var instanceDescription: String {
        guard let first = instances.first else { return "" }
        if let socket = first.socketDir, !socket.isEmpty {
            return " (port \(first.port), socket \(socket))"
        }
        return " (port \(first.port))"
    }

    private func loadOverview() async {
        guard let api = session.api else {
            if overview.value == nil { overview = .loading }
            return
        }
        guard session.capabilities.postgres else { return }

        // Instances first: knowing that something is listening is what turns a
        // sign-in failure from a mystery into a sentence.
        if let found = try? await api.databaseInstances() {
            instances = found
        }

        do {
            overview = .loaded(try await api.postgresOverview())
        } catch let error as ServerOSError {
            overview = .failed(error)
        } catch {
            overview = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func loadCurrentTab() async {
        guard let api = session.api, session.capabilities.postgres else { return }

        switch tab {
        case .databases:
            await load(
                current: databases.value,
                fetch: { try await api.postgresDatabases() },
                assign: { databases = $0 }
            )
        case .tables:
            await load(
                current: tables.value,
                fetch: { try await api.postgresTables(database: selectedDatabase) },
                assign: { tables = $0 }
            )
        case .connections:
            await load(
                current: connections.value,
                fetch: { try await api.postgresConnections(includeQueryText: showsQueryText) },
                assign: { connections = $0 }
            )
        case .roles:
            await load(
                current: roles.value,
                fetch: { try await api.postgresRoles() },
                assign: { roles = $0 }
            )
        }
    }

    /// One loader for four identically-shaped fetches.
    ///
    /// A failed refresh keeps whatever is already on screen: the shell's stale
    /// banner says the server is out of touch, and replacing a readable table
    /// with an error page would lose information the user was in the middle of
    /// reading.
    private func load<Item>(
        current: [Item]?,
        fetch: () async throws -> [Item],
        assign: (ScreenState<[Item]>) -> Void
    ) async {
        if current == nil { assign(.loading) }
        do {
            let items = try await fetch()
            assign(items.isEmpty ? .empty : .loaded(items))
        } catch let error as ServerOSError {
            if current == nil { assign(.failed(error)) }
        } catch {
            if current == nil {
                assign(.failed(ServerOSError.transport(error, serverName: session.name)))
            }
        }
    }

    // MARK: - Value mapping

    /// The agent's word for PostgreSQL's condition, in the app's vocabulary.
    private static func healthState(_ raw: String) -> HealthState {
        switch raw {
        case "healthy": return .healthy
        case "warning": return .warning
        case "critical": return .critical
        case "unreachable", "offline": return .offline
        default: return .unknown
        }
    }

    private static func healthSummary(_ raw: String) -> String {
        switch raw {
        case "healthy": return "PostgreSQL is accepting connections and serving normally."
        case "warning": return "PostgreSQL is running, but something about it needs attention."
        case "critical": return "PostgreSQL is in trouble."
        case "unreachable", "offline": return "ServerOS can't reach PostgreSQL on this server."
        default: return "ServerOS can't tell what condition PostgreSQL is in."
        }
    }

    private static func connectionsLabel(current: Int?, maximum: Int?) -> String {
        switch (current, maximum) {
        case let (.some(current), .some(maximum)):
            return "\(Formatting.count(current)) of \(Formatting.count(maximum)) connections"
        case let (.some(current), .none):
            return "\(Formatting.count(current)) connections"
        default:
            return "Unknown"
        }
    }

    private func cacheTint(_ ratio: Double?) -> Color {
        guard let ratio else { return Palette.textMuted }
        if ratio >= 99 { return Palette.healthy }
        if ratio >= 95 { return Palette.warning }
        return Palette.critical
    }

    private func cacheAdvice(_ ratio: Double?) -> String {
        guard let ratio else {
            return "PostgreSQL didn't report how often it served a read from memory."
        }
        if ratio >= 99 {
            return "How often a read was served from memory instead of disk. 99% or better is what a healthy "
                + "server looks like."
        }
        if ratio >= 95 {
            return "How often a read was served from memory instead of disk. Healthy servers sit at 99% or better; "
                + "this one is going to disk more than it should."
        }
        return "How often a read was served from memory instead of disk. Below 95% usually means shared_buffers is "
            + "too small for this working set, or a large scan has just pushed everything out of cache."
    }

    private static func rollbackLabel(_ value: PostgresOverview) -> String? {
        guard let rolledBack = value.transactionsRolledBack else { return nil }
        guard let committed = value.transactionsCommitted, committed > 0 else {
            return Formatting.count(rolledBack)
        }
        let share = Double(rolledBack) / Double(committed + rolledBack) * 100
        return "\(Formatting.count(rolledBack)) (\(Formatting.decimal(share, places: 1))%)"
    }

    private static func connectionLimit(_ limit: Int?) -> String {
        guard let limit else { return "Unknown" }
        // PostgreSQL spells "no limit" as -1 everywhere; nobody should have to
        // know that.
        return limit < 0 ? "Unlimited" : Formatting.count(limit)
    }

    private static func applicationName(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty else { return "Not set" }
        return raw
    }

    private static func connectionState(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty else { return "Unknown" }
        switch raw {
        case "active": return "Active"
        case "idle": return "Idle"
        case "idle in transaction": return "Idle in txn"
        case "idle in transaction (aborted)": return "Aborted txn"
        case "fastpath function call": return "Fastpath"
        case "disabled": return "Disabled"
        default: return raw
        }
    }

    private static func connectionStateTint(_ raw: String?) -> Color {
        switch raw {
        case "active": return Palette.healthy
        // An idle transaction holds locks and blocks vacuum; it is the one
        // connection state worth flagging on sight.
        case "idle in transaction", "idle in transaction (aborted)": return Palette.warning
        default: return Palette.inactive
        }
    }

    private static func privilegeTint(_ privilege: String) -> Color {
        switch privilege {
        case "Superuser", "Bypasses RLS": return Palette.warning
        case "Cannot log in": return Palette.inactive
        default: return Palette.informational
        }
    }

    private static func scanCount(_ value: Int64?) -> String {
        value.map { Formatting.count($0) } ?? "—"
    }

    /// A table read mostly by sequential scan is the classic missing-index shape.
    ///
    /// The thresholds are deliberately conservative: a small table is *supposed*
    /// to be scanned — reading 200 rows outright is cheaper than an index lookup
    /// — so flagging one would train the reader to ignore the flag.
    private static func isSeqScanHeavy(_ table: PostgresTable) -> Bool {
        guard let seq = table.seqScans, seq >= 1_000 else { return false }
        guard (table.rowsEstimate ?? 0) >= 10_000 else { return false }
        let index = table.indexScans ?? 0
        return seq > index * 10
    }

    /// The agent reports these timestamps as `extract(epoch FROM …)`, and the
    /// wire model carries them as text — so a value may arrive as "1757600000"
    /// or as something already formatted. Parse the epoch when we can and show
    /// exactly what we were given when we cannot: inventing a date out of a
    /// string we did not understand would be worse than showing the string.
    private static func timeDescription(_ raw: String?, whenMissing: String = "Never") -> String {
        guard let raw, !raw.isEmpty else { return whenMissing }
        if let epoch = Int64(raw), epoch > 0 {
            return Formatting.relative(unixSeconds: epoch)
        }
        return raw
    }

    /// How long a connection has been in its current state.
    private static func elapsed(since epoch: Int64?) -> String {
        guard let epoch, epoch > 0 else { return "—" }
        let seconds = Int(Date().timeIntervalSince1970) - Int(epoch)
        guard seconds >= 0 else { return "—" }
        return Formatting.durationCompact(seconds: seconds)
    }
}

// MARK: - Tabs

/// The four inventories, in the order someone investigating works through them.
private enum DatabaseTab: String, CaseIterable, Hashable {
    case databases, tables, connections, roles

    var title: String {
        switch self {
        case .databases: return "Databases"
        case .tables: return "Tables"
        case .connections: return "Connections"
        case .roles: return "Roles"
        }
    }
}

// MARK: - Preview

private struct DatabasesPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        DatabasesSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1080, height: 720)
            .onAppear { session.connect() }
    }
}

#Preview("Databases") {
    DatabasesPreviewHost()
}
