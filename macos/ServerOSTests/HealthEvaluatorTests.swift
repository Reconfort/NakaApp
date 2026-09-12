//  HealthEvaluatorTests.swift
//  ServerOSTests
//
//  The dot, the headline, the sentence and the button.
//
//  `HealthEvaluator` decides the single most visible thing in the product, and
//  it is pure — inputs in, a verdict out — so it can be exercised as a table.
//  Each case below is a state a real server reaches, and the assertion is the
//  exact words a person would read, because the wording *is* the feature: a
//  warning nobody understands is a warning nobody acts on.
//
//  The thresholds are judgement calls rather than physics, so several cases sit
//  deliberately on both sides of a boundary. If someone retunes a threshold,
//  these fail and force the decision to be made on purpose.

import XCTest
@testable import ServerOS

final class HealthEvaluatorTests: XCTestCase {

    // MARK: - Builders

    private func filesystem(
        _ mountPoint: String,
        usage: Double?,
        available: Int64? = 20_000_000_000
    ) -> DiskMetrics.Filesystem {
        DiskMetrics.Filesystem(
            device: "/dev/nvme0n1",
            mountPoint: mountPoint,
            fstype: "ext4",
            totalBytes: 500_000_000_000,
            usedBytes: usage.map { Int64(500_000_000_000 * $0 / 100) },
            availableBytes: available,
            usagePercent: usage,
            inodesTotal: nil,
            inodesUsed: nil
        )
    }

    private func metrics(
        cpuPercent: Double = 10,
        loadOne: Double = 0.4,
        loadFive: Double = 0.4,
        cores: Int = 4,
        memoryPercent: Double = 40,
        swapTotalBytes: Int64 = 4_294_967_296,
        swapPercent: Double = 0,
        filesystems: [DiskMetrics.Filesystem]? = nil,
        warmingUp: Bool = false
    ) -> Metrics {
        let disks = filesystems ?? [filesystem("/", usage: 40)]
        return Metrics(
            sampledAt: 1_789_210_504,
            cpu: CPUMetrics(
                usagePercent: cpuPercent,
                userPercent: cpuPercent * 0.7,
                systemPercent: cpuPercent * 0.2,
                iowaitPercent: cpuPercent * 0.1,
                perCore: Array(repeating: cpuPercent, count: cores),
                loadAverage: LoadAverage(one: loadOne, five: loadFive, fifteen: loadFive),
                coreCount: cores
            ),
            memory: MemoryMetrics(
                totalBytes: 16_000_000_000,
                usedBytes: Int64(16_000_000_000 * memoryPercent / 100),
                availableBytes: Int64(16_000_000_000 * (100 - memoryPercent) / 100),
                cachedBytes: 1_000_000_000,
                buffersBytes: 100_000_000,
                usagePercent: memoryPercent,
                swapTotalBytes: swapTotalBytes,
                swapUsedBytes: Int64(Double(swapTotalBytes) * swapPercent / 100),
                swapUsagePercent: swapPercent
            ),
            disk: DiskMetrics(
                totalBytes: 500_000_000_000,
                usedBytes: 200_000_000_000,
                availableBytes: 300_000_000_000,
                usagePercent: 40,
                filesystems: disks
            ),
            network: NetworkMetrics(
                rxBytesTotal: 1_000,
                txBytesTotal: 1_000,
                rxBytesPerSec: 0,
                txBytesPerSec: 0,
                interfaces: []
            ),
            warmingUp: warmingUp
        )
    }

    // MARK: - Reachability

    func testHealthyWhenNothingIsWrong() {
        let verdict = HealthEvaluator.evaluate(HealthInput(metrics: metrics()))
        XCTAssertEqual(verdict.state, .healthy)
        XCTAssertEqual(verdict.summary, "Everything is operating normally.")
        XCTAssertNil(verdict.reason)
        XCTAssertEqual(verdict.action, .none)
    }

    func testUnreachableBeatsEverythingElse() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            isReachable: false,
            metrics: metrics(memoryPercent: 99),
            failedServices: ["nginx"]
        ))
        XCTAssertEqual(verdict, ServerHealth.offline)
        XCTAssertEqual(verdict.state, .offline)
        XCTAssertEqual(verdict.action, .reconnect)
    }

    func testSilenceBeyondTheThresholdReadsAsOffline() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            secondsSinceLastContact: 200,
            metrics: metrics()
        ))
        XCTAssertEqual(verdict.state, .offline)
        XCTAssertEqual(verdict.summary, "ServerOS can't reach this server.")
        XCTAssertEqual(
            verdict.reason,
            "No response for 3 minutes. The server may be offline, or the connection may have dropped."
        )
        XCTAssertEqual(verdict.action, .reconnect)
    }

    func testSilenceInsideTheThresholdIsNotOffline() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            secondsSinceLastContact: 89,
            metrics: metrics()
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testNothingHeardYetIsUnknownRatherThanHealthy() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            secondsSinceLastContact: nil,
            metrics: nil
        ))
        XCTAssertEqual(verdict, ServerHealth.unknown)
        XCTAssertEqual(verdict.state, .unknown)
    }

    func testContactWithoutMetricsIsStillHealthy() {
        // The agent answered; we simply have no sample yet. That is not a
        // problem to report.
        let verdict = HealthEvaluator.evaluate(HealthInput(secondsSinceLastContact: 2, metrics: nil))
        XCTAssertEqual(verdict.state, .healthy)
    }

    // MARK: - Storage

    func testDiskAtTheWarningThreshold() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 80)])
        ))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "Storage is filling up.")
        XCTAssertEqual(verdict.reason, "The root filesystem is 80% full.")
        XCTAssertEqual(verdict.action, .openStorage)
    }

    func testDiskJustBelowTheWarningThreshold() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 79.4)])
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testDiskAtTheCriticalThresholdNamesWhatIsLeft() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 96, available: 8_000_000_000)])
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "Storage is almost full.")
        XCTAssertEqual(verdict.reason?.hasPrefix("The root filesystem is 96% full — only "), true)
        XCTAssertEqual(verdict.action, .openStorage)
    }

    func testDiskCriticalWithoutAFreeFigureStillReads() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 99, available: nil)])
        ))
        XCTAssertEqual(verdict.reason, "The root filesystem is 99% full.")
    }

    func testAFullVolumeIsNotAveragedAwayByARoomyOne() {
        // The whole reason disk is judged per filesystem: a full `/var` and a
        // roomy `/` average out to "fine" and are anything but.
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [
                filesystem("/", usage: 12),
                filesystem("/var", usage: 97),
            ])
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.reason?.hasPrefix("/var is 97% full"), true)
    }

    func testAFilesystemWithNoUsageFigureIsIgnored() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: nil)])
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testOnlyTheWorstFilesystemIsReported() {
        let findings = HealthEvaluator.findings(for: HealthInput(
            metrics: metrics(filesystems: [
                filesystem("/", usage: 85),
                filesystem("/var", usage: 88),
                filesystem("/srv", usage: 97),
            ])
        ))
        XCTAssertEqual(findings.filter { $0.action == .openStorage }.count, 1)
    }

    // MARK: - Memory

    func testMemoryAtTheWarningThreshold() {
        let verdict = HealthEvaluator.evaluate(HealthInput(metrics: metrics(memoryPercent: 90)))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "Memory is running low.")
        XCTAssertEqual(verdict.reason, "90% of memory is in use.")
        XCTAssertEqual(verdict.action, .openProcesses)
    }

    func testMemoryJustBelowTheWarningThreshold() {
        let verdict = HealthEvaluator.evaluate(HealthInput(metrics: metrics(memoryPercent: 89.4)))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testMemoryAtTheCriticalThresholdWarnsAboutTheOOMKiller() {
        let verdict = HealthEvaluator.evaluate(HealthInput(metrics: metrics(memoryPercent: 97)))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "Memory is nearly exhausted.")
        XCTAssertEqual(
            verdict.reason,
            "97% of memory is in use. The kernel may start killing processes."
        )
    }

    func testSwappingIsWorthSayingEvenWhenMemoryLooksFine() {
        // Swapping is felt as latency long before memory reads as full.
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(memoryPercent: 55, swapPercent: 60)
        ))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "The server is swapping.")
        XCTAssertEqual(
            verdict.reason,
            "60% of swap is in use, which usually means memory pressure."
        )
    }

    func testAServerWithNoSwapIsNeverReportedAsSwapping() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(memoryPercent: 55, swapTotalBytes: 0, swapPercent: 90)
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testSwapJustBelowTheThresholdIsQuiet() {
        let verdict = HealthEvaluator.evaluate(HealthInput(metrics: metrics(swapPercent: 49)))
        XCTAssertEqual(verdict.state, .healthy)
    }

    // MARK: - CPU and load

    func testSustainedLoadPerCoreIsAWarning() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(loadOne: 8, loadFive: 8, cores: 4)
        ))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "The server is under heavy load.")
        XCTAssertEqual(
            verdict.reason,
            "Load average is 8.00 across 4 cores — about 2.0× what it can run at once."
        )
        XCTAssertEqual(verdict.action, .openProcesses)
    }

    func testLoadJustBelowTheThresholdIsQuiet() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(loadOne: 7.6, loadFive: 7.6, cores: 4)
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testASingleCoreServerPhrasesTheCoreCountCorrectly() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(loadOne: 3, loadFive: 3, cores: 1)
        ))
        XCTAssertEqual(verdict.reason?.contains("across 1 core —"), true)
    }

    func testHighCPUWithAgreeingLoadIsSaturation() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(cpuPercent: 92, loadOne: 4, loadFive: 4, cores: 4)
        ))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "CPU is saturated.")
        XCTAssertEqual(verdict.reason, "CPU has been at 92% with a load average of 4.00.")
    }

    func testHighCPUWithLowLoadIsJustABusyMoment() {
        // A single sample says nothing about sustained load, and crying wolf on
        // a momentary spike is how a dashboard becomes background noise.
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(cpuPercent: 98, loadOne: 0.6, loadFive: 0.6, cores: 4)
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testWarmingUpSuppressesCPUFindings() {
        // The first sample after connecting is always zero, and the load
        // average has had no time to mean anything.
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(cpuPercent: 99, loadOne: 20, loadFive: 20, cores: 4, warmingUp: true)
        ))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testWarmingUpDoesNotSuppressDiskFindings() {
        // Disk usage is a level, not a rate — it is true on the first sample.
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 97)], warmingUp: true)
        ))
        XCTAssertEqual(verdict.state, .critical)
    }

    // MARK: - Services

    func testOneFailedServiceIsNamed() {
        let verdict = HealthEvaluator.evaluate(HealthInput(failedServices: ["nginx"]))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "nginx has failed.")
        XCTAssertEqual(verdict.reason, "nginx stopped unexpectedly and has not recovered.")
        XCTAssertEqual(verdict.action, .openServices(unit: "nginx"))
    }

    func testSeveralFailedServicesAreCounted() {
        let verdict = HealthEvaluator.evaluate(HealthInput(failedServices: ["nginx", "redis"]))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "2 services have failed.")
        XCTAssertEqual(verdict.reason, "nginx and redis stopped unexpectedly and have not recovered.")
        XCTAssertEqual(verdict.action, .openServices(unit: nil))
    }

    func testManyFailedServicesAreSummarised() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            failedServices: ["nginx", "redis", "postgres", "cron"]
        ))
        XCTAssertEqual(verdict.summary, "4 services have failed.")
        XCTAssertEqual(verdict.reason?.hasPrefix("nginx, redis and 2 others"), true)
    }

    // MARK: - Containers

    func testOneUnhealthyContainerIsCritical() {
        let verdict = HealthEvaluator.evaluate(HealthInput(unhealthyContainers: ["estatify-api"]))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "estatify-api is unhealthy.")
        XCTAssertEqual(
            verdict.reason,
            "estatify-api is running but failing its health check."
        )
        XCTAssertEqual(verdict.action, .openDocker(containerID: "estatify-api"))
    }

    func testSeveralUnhealthyContainersAreCounted() {
        let verdict = HealthEvaluator.evaluate(HealthInput(unhealthyContainers: ["api", "web"]))
        XCTAssertEqual(verdict.summary, "2 containers are unhealthy.")
        XCTAssertEqual(verdict.reason, "api and web are running but failing their health check.")
        XCTAssertEqual(verdict.action, .openDocker(containerID: nil))
    }

    func testOneStoppedContainerIsOnlyAWarning() {
        // A stopped container is often deliberate — a migration job, a one-off.
        let verdict = HealthEvaluator.evaluate(HealthInput(stoppedContainers: ["estatify-migrate"]))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.summary, "estatify-migrate is not running.")
        XCTAssertEqual(verdict.reason, "estatify-migrate is stopped.")
        XCTAssertEqual(verdict.action, .openDocker(containerID: "estatify-migrate"))
    }

    func testSeveralStoppedContainersAreCounted() {
        // Past the list limit the names are summarised, so a health reason
        // cannot run to three lines when twelve things are wrong.
        let verdict = HealthEvaluator.evaluate(HealthInput(stoppedContainers: ["a", "b", "c"]))
        XCTAssertEqual(verdict.summary, "3 containers are not running.")
        XCTAssertEqual(verdict.reason, "a, b and 1 other are stopped.")
    }

    // MARK: - PostgreSQL

    func testPostgresCriticalUsesTheDatabasesOwnReason() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            postgresHealth: "critical",
            postgresReason: "Connection usage is at 98% of max_connections."
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "PostgreSQL needs attention.")
        XCTAssertEqual(verdict.reason, "Connection usage is at 98% of max_connections.")
        XCTAssertEqual(verdict.action, .openDatabases)
    }

    func testPostgresWarningWithoutAReasonStillReads() {
        let verdict = HealthEvaluator.evaluate(HealthInput(postgresHealth: "warning"))
        XCTAssertEqual(verdict.state, .warning)
        XCTAssertEqual(verdict.reason, "The database reported a warning.")
    }

    func testPostgresHealthyProducesNoFinding() {
        let verdict = HealthEvaluator.evaluate(HealthInput(postgresHealth: "healthy"))
        XCTAssertEqual(verdict.state, .healthy)
    }

    func testAnUnrecognisedPostgresHealthIsIgnoredRatherThanGuessed() {
        let verdict = HealthEvaluator.evaluate(HealthInput(postgresHealth: "degraded"))
        XCTAssertEqual(verdict.state, .healthy)
    }

    // MARK: - Rolling up

    func testCriticalOutranksWarning() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 85)]),
            stoppedContainers: ["worker"],
            failedServices: ["nginx"]
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(verdict.summary, "nginx has failed.")
    }

    func testTwoProblemsAtTheSameSeveritySayHowMany() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            unhealthyContainers: ["api"],
            failedServices: ["nginx"]
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(
            verdict.reason?.hasSuffix("There is also 1 other issue at this level."),
            true,
            "Got: \(verdict.reason ?? "nil")"
        )
    }

    func testThreeProblemsAtTheSameSeverityPluralise() {
        let verdict = HealthEvaluator.evaluate(HealthInput(
            metrics: metrics(memoryPercent: 98),
            unhealthyContainers: ["api"],
            failedServices: ["nginx"]
        ))
        XCTAssertEqual(verdict.state, .critical)
        XCTAssertEqual(
            verdict.reason?.hasSuffix("There are also 2 other issues at this level."),
            true,
            "Got: \(verdict.reason ?? "nil")"
        )
    }

    func testFindingsComeBackMostSevereFirst() {
        let findings = HealthEvaluator.findings(for: HealthInput(
            metrics: metrics(filesystems: [filesystem("/", usage: 85)]),
            stoppedContainers: ["worker"],
            failedServices: ["nginx"]
        ))
        XCTAssertEqual(findings.count, 3)
        XCTAssertEqual(findings[0].state, .critical)
        XCTAssertEqual(findings[1].state, .warning)
        XCTAssertEqual(findings[2].state, .warning)
    }

    func testAHealthyServerHasNoFindingsAtAll() {
        XCTAssertTrue(HealthEvaluator.findings(for: HealthInput(metrics: metrics())).isEmpty)
    }

    // MARK: - Fleet summary

    func testFleetSummaryWithNoServers() {
        XCTAssertEqual(HealthEvaluator.fleetSummary([]), "No servers yet.")
    }

    func testFleetSummaryWithOneHealthyServer() {
        let healthy = ServerHealth(state: .healthy, summary: "fine")
        XCTAssertEqual(HealthEvaluator.fleetSummary([healthy]), "Your server is operating normally.")
    }

    func testFleetSummaryWithSeveralHealthyServers() {
        let healthy = ServerHealth(state: .healthy, summary: "fine")
        XCTAssertEqual(
            HealthEvaluator.fleetSummary([healthy, healthy, healthy]),
            "All 3 servers are operating normally."
        )
    }

    func testFleetSummaryLeadsWithTheUrgentCount() {
        let critical = ServerHealth(state: .critical, summary: "bad")
        let healthy = ServerHealth(state: .healthy, summary: "fine")
        XCTAssertEqual(
            HealthEvaluator.fleetSummary([critical, healthy]),
            "1 needs attention urgently."
        )
    }

    func testFleetSummaryCombinesEveryKindOfProblem() {
        let critical = ServerHealth(state: .critical, summary: "bad")
        let warning = ServerHealth(state: .warning, summary: "meh")
        XCTAssertEqual(
            HealthEvaluator.fleetSummary([critical, ServerHealth.offline, warning]),
            "1 needs attention urgently, 1 is offline, 1 has warnings."
        )
    }

    func testFleetSummaryPluralises() {
        let critical = ServerHealth(state: .critical, summary: "bad")
        let warning = ServerHealth(state: .warning, summary: "meh")
        XCTAssertEqual(
            HealthEvaluator.fleetSummary([critical, critical, warning, warning]),
            "2 need attention urgently, 2 have warnings."
        )
    }

    // MARK: - The state itself

    func testSeverityOrdering() {
        XCTAssertLessThan(HealthState.unknown, HealthState.healthy)
        XCTAssertLessThan(HealthState.healthy, HealthState.warning)
        XCTAssertLessThan(HealthState.warning, HealthState.critical)
        XCTAssertLessThan(HealthState.critical, HealthState.offline)
    }

    func testEveryStateCarriesWordsAndAShapeNotJustAColour() {
        // Never communicate state through colour alone.
        for state in HealthState.allCases {
            XCTAssertFalse(state.label.isEmpty, "\(state) has no label")
            XCTAssertFalse(state.symbolName.isEmpty, "\(state) has no symbol")
            XCTAssertFalse(state.accessibilityLabel.isEmpty, "\(state) has no spoken label")
        }
        XCTAssertEqual(HealthState.warning.label, "Needs Attention")
        XCTAssertEqual(HealthState.healthy.symbolName, "checkmark.circle.fill")
    }

    func testActionTitlesChangeWithTheirTarget() {
        XCTAssertNil(HealthAction.none.title)
        XCTAssertEqual(HealthAction.openStorage.title, "Review Storage")
        XCTAssertEqual(HealthAction.openDocker(containerID: nil).title, "Open Docker")
        XCTAssertEqual(HealthAction.openDocker(containerID: "api").title, "Open Container")
        XCTAssertEqual(HealthAction.openServices(unit: nil).title, "Open Services")
        XCTAssertEqual(HealthAction.openServices(unit: "nginx").title, "Open Service")
        XCTAssertEqual(HealthAction.reconnect.title, "Reconnect")
        XCTAssertEqual(HealthAction.openLogs.title, "View Logs")
        XCTAssertEqual(HealthAction.openProcesses.title, "Open Processes")
        XCTAssertEqual(HealthAction.openDatabases.title, "Open Databases")
    }
}
