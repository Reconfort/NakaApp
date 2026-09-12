//  WireDecodingTests.swift
//  ServerOSTests
//
//  The contract test.
//
//  Every file in `macos/fixtures/` is a response captured from a real agent.
//  This decodes all of them into the models the app actually uses and asserts
//  on specific values — not merely that decoding did not throw.
//
//  Asserting on values matters more than it looks. A `CodingKey` typo makes an
//  optional field decode as nil rather than failing, so a test that only checks
//  "it decoded" passes happily while the Docker screen shows no ports and the
//  users screen shows no last-login. Every optional that has a value in the
//  fixture is asserted to have it, and every optional that is genuinely absent
//  is asserted to be nil — because "the agent did not say" is a state the UI
//  renders differently from zero, and both need to survive.
//
//  When this test fails, the agent and the app have disagreed. Do not "fix" it
//  by loosening the assertion.

import XCTest
@testable import ServerOS

final class WireDecodingTests: XCTestCase {

    // MARK: - Coverage

    func testEveryFixtureIsAccountedFor() throws {
        // The list in `Fixtures.allNames` is what the rest of this file walks
        // through. If someone captures a new endpoint and does not add a test,
        // this notices.
        // Skip rather than fail when running from a bundle with no checkout
        // alongside it — the per-fixture tests below still run.
        let contents = (try? FileManager.default
            .contentsOfDirectory(atPath: Fixtures.repositoryDirectory.path)) ?? []
        let onDisk = contents.filter { $0.hasSuffix(".json") }.sorted()

        try XCTSkipIf(onDisk.isEmpty, "No repository checkout next to the test bundle.")
        XCTAssertEqual(onDisk, Fixtures.allNames.sorted(), "A fixture exists that no test decodes.")
    }

    func testEveryFixtureIsValidJSON() throws {
        for name in Fixtures.allNames {
            let raw = try Fixtures.data(name)
            XCTAssertNoThrow(
                try JSONSerialization.jsonObject(with: raw),
                "\(name) is not valid JSON"
            )
        }
    }

    // MARK: - Health and capabilities

    func testHealthDecodes() throws {
        let health = try Fixtures.decode(AgentHealth.self, from: "health.json")

        XCTAssertEqual(health.status, "ok")
        XCTAssertTrue(health.isOK)
        XCTAssertEqual(health.agentVersion, "0.1.0")
        XCTAssertEqual(health.apiVersion, "1")
        XCTAssertEqual(health.serverID, "srv_563016eaa2ea5baa")
        XCTAssertEqual(health.uptimeSeconds, 20)

        XCTAssertTrue(health.capabilities.docker)
        XCTAssertEqual(health.capabilities.dockerAPIVersion, "1.43")
        // This host has no systemd, and the app must show no Services section
        // rather than one that fails when opened.
        XCTAssertFalse(health.capabilities.services)
        XCTAssertNil(health.capabilities.serviceBackend)
        XCTAssertFalse(health.capabilities.journal)
        XCTAssertTrue(health.capabilities.postgres)
    }

    func testCapabilitiesDecodes() throws {
        let capabilities = try Fixtures.decode(AgentCapabilities.self, from: "capabilities.json")

        XCTAssertTrue(capabilities.metrics)
        XCTAssertTrue(capabilities.processes)
        XCTAssertTrue(capabilities.users)
        XCTAssertTrue(capabilities.files)
        XCTAssertTrue(capabilities.logs)
        XCTAssertTrue(capabilities.docker)
        XCTAssertEqual(capabilities.dockerAPIVersion, "1.43")
        XCTAssertFalse(capabilities.services)
        XCTAssertNil(capabilities.serviceBackend)
        XCTAssertFalse(capabilities.journal)
        XCTAssertTrue(capabilities.postgres)
    }

    // MARK: - System

    func testSystemDecodes() throws {
        let system = try Fixtures.decode(SystemInfo.self, from: "system.json")

        XCTAssertEqual(system.hostname, "vm")
        XCTAssertEqual(system.os.name, "Ubuntu")
        XCTAssertEqual(system.os.version, "24.04.4 LTS")
        XCTAssertEqual(system.os.id, "ubuntu")
        XCTAssertEqual(system.os.pretty, "Ubuntu 24.04.4 LTS")
        XCTAssertEqual(system.kernel, "6.18.44-fc-v24")
        XCTAssertEqual(system.architecture, "x86_64")

        XCTAssertEqual(system.cpu.model, "Intel(R) Xeon(R) Processor @ 2.80GHz")
        XCTAssertEqual(system.cpu.cores, 2)
        XCTAssertEqual(system.cpu.threads, 2)
        XCTAssertEqual(system.cpu.mhz ?? 0, 2800.0, accuracy: 0.001)

        XCTAssertEqual(system.memoryTotalBytes, 8_413_380_608)
        XCTAssertEqual(system.swapTotalBytes, 0)
        XCTAssertEqual(system.bootTime, 1_789_198_631)
        XCTAssertEqual(system.uptimeSeconds, 11_873)
        XCTAssertEqual(system.virtualization, "virtualized")

        XCTAssertEqual(system.loadAverage.one, 0.27, accuracy: 0.0001)
        XCTAssertEqual(system.loadAverage.five, 0.25, accuracy: 0.0001)
        XCTAssertEqual(system.loadAverage.fifteen, 0.12, accuracy: 0.0001)

        XCTAssertEqual(system.agent.version, "0.1.0")
        XCTAssertEqual(system.agent.uptimeSeconds, 20)
        XCTAssertEqual(system.agent.startedAt, 1_789_210_483)
        XCTAssertTrue(system.agent.enrolled)
    }

    // MARK: - Metrics

    func testMetricsDecodes() throws {
        let metrics = try Fixtures.decode(Metrics.self, from: "metrics.json")

        XCTAssertEqual(metrics.sampledAt, 1_789_210_504)
        // The first sample after connecting has no baseline, and the UI must
        // show a placeholder rather than a confident 0%.
        XCTAssertEqual(metrics.warmingUp, true)
        XCTAssertTrue(metrics.isWarmingUp)

        XCTAssertEqual(metrics.cpu.usagePercent, 0.0, accuracy: 0.0001)
        XCTAssertEqual(metrics.cpu.coreCount, 2)
        XCTAssertEqual(metrics.cpu.perCore.count, 2)
        XCTAssertEqual(metrics.cpu.loadAverage.five, 0.25, accuracy: 0.0001)

        XCTAssertEqual(metrics.memory.totalBytes, 8_413_380_608)
        XCTAssertEqual(metrics.memory.usedBytes, 899_051_520)
        XCTAssertEqual(metrics.memory.availableBytes, 7_514_329_088)
        XCTAssertEqual(metrics.memory.cachedBytes, 1_647_489_024)
        XCTAssertEqual(metrics.memory.buffersBytes, 8_847_360)
        XCTAssertEqual(metrics.memory.usagePercent, 10.7, accuracy: 0.0001)
        XCTAssertEqual(metrics.memory.swapTotalBytes, 0)
        XCTAssertFalse(metrics.memory.hasSwap)

        // Disk totals are present but `used` is not: this host's agent could
        // not read usage for every filesystem, and "unknown" must survive as
        // nil rather than becoming 0.
        XCTAssertEqual(metrics.disk.totalBytes, 275_174_858_752)
        XCTAssertNil(metrics.disk.usedBytes)
        XCTAssertNil(metrics.disk.usagePercent)
        XCTAssertEqual(metrics.disk.filesystems.count, 6)

        let root = metrics.disk.filesystems[0]
        XCTAssertEqual(root.device, "/dev/vda")
        XCTAssertEqual(root.mountPoint, "/")
        XCTAssertEqual(root.fstype, "ext4")
        XCTAssertEqual(root.totalBytes, 274_877_906_944)
        XCTAssertNil(root.usedBytes)
        XCTAssertNil(root.usagePercent)
        XCTAssertEqual(root.id, "/")

        let tmpfs = metrics.disk.filesystems[3]
        XCTAssertEqual(tmpfs.device, "tmpfs")
        XCTAssertEqual(tmpfs.fstype, "tmpfs")
        XCTAssertNil(tmpfs.totalBytes)

        XCTAssertEqual(metrics.network.rxBytesTotal, 72_194_764)
        XCTAssertEqual(metrics.network.txBytesTotal, 187_954_499)
        XCTAssertEqual(metrics.network.interfaces.count, 4)

        let interfaces = metrics.network.interfaces
        XCTAssertEqual(interfaces[0].name, "ifb0")
        XCTAssertFalse(interfaces[0].up)
        XCTAssertEqual(interfaces[2].name, "eth0")
        XCTAssertTrue(interfaces[2].up)
        XCTAssertEqual(interfaces[2].rxBytes, 72_194_680)
        XCTAssertEqual(interfaces[2].txBytes, 187_954_499)
        XCTAssertEqual(interfaces[2].rxErrors, 0)
    }

    // MARK: - Activity

    func testActivityDecodes() throws {
        let page = try Fixtures.decode(AgentCollection<ActivityEvent>.self, from: "activity.json")

        XCTAssertEqual(page.total, 1)
        XCTAssertEqual(page.items.count, 1)

        let event = page.items[0]
        XCTAssertEqual(event.id, 1)
        XCTAssertEqual(event.at, 1_789_210_483)
        XCTAssertEqual(event.action, "agent.start")
        XCTAssertEqual(event.resourceType, "agent")
        XCTAssertEqual(event.resourceID, "srv_563016eaa2ea5baa")
        XCTAssertEqual(event.actor, "system")
        XCTAssertNil(event.peer)
        XCTAssertEqual(event.outcome, "succeeded")
        XCTAssertTrue(event.succeeded)
        XCTAssertEqual(event.summary, "ServerOS agent 0.1.0 started")
    }

    // MARK: - Processes

    func testProcessesDecode() throws {
        let list = try Fixtures.decode(ProcessList.self, from: "processes.json")

        XCTAssertEqual(list.total, 5)
        XCTAssertEqual(list.items.count, 5)
        // The list echoes the query it answered, so a stale response arriving
        // after the user re-sorted can be recognised and dropped.
        XCTAssertEqual(list.sort, "cpu")
        XCTAssertEqual(list.limit, 5)

        let first = list.items[0]
        XCTAssertEqual(first.pid, 468)
        XCTAssertEqual(first.ppid, 1)
        XCTAssertEqual(first.name, "claude")
        XCTAssertEqual(first.user, "root")
        XCTAssertEqual(first.uid, 0)
        XCTAssertEqual(first.state, "sleeping")
        XCTAssertEqual(first.cpuPercent, 3.7, accuracy: 0.0001)
        XCTAssertEqual(first.memoryBytes, 436_232_192)
        XCTAssertEqual(first.memoryPercent, 5.2, accuracy: 0.0001)
        XCTAssertEqual(first.threads, 9)
        XCTAssertEqual(first.startedAt, 1_789_198_634)
        XCTAssertEqual(first.id, 468)
        XCTAssertTrue(first.command.hasPrefix("/opt/node22/bin/claude"))
    }

    // MARK: - Users and groups

    func testUsersDecode() throws {
        let list = try Fixtures.decode(UserList.self, from: "users.json")

        XCTAssertEqual(list.total, 26)
        XCTAssertEqual(list.items.count, 26)
        XCTAssertEqual(list.people, 2)
        XCTAssertEqual(list.system, 24)

        let root = list.items[0]
        XCTAssertEqual(root.username, "root")
        XCTAssertEqual(root.uid, 0)
        XCTAssertEqual(root.gid, 0)
        XCTAssertEqual(root.fullName, "root")
        XCTAssertEqual(root.home, "/root")
        XCTAssertEqual(root.shell, "/bin/bash")
        XCTAssertEqual(root.groups, ["root"])
        XCTAssertTrue(root.isSystem)
        XCTAssertFalse(root.canSudo)
        XCTAssertEqual(root.locked, true)
        XCTAssertEqual(root.hasPassword, false)
        // Not readable on this host, and "unknown" must not become 0.
        XCTAssertNil(root.sshKeyCount)
        XCTAssertNil(root.lastLogin)
        XCTAssertEqual(root.id, "root")

        let daemon = list.items[1]
        XCTAssertEqual(daemon.username, "daemon")
        XCTAssertEqual(daemon.shell, "/usr/sbin/nologin")
        XCTAssertFalse(daemon.isLoginUser)
    }

    func testGroupsDecode() throws {
        let page = try Fixtures.decode(AgentCollection<LinuxGroup>.self, from: "groups.json")

        XCTAssertEqual(page.total, 49)
        XCTAssertEqual(page.items.count, 49)
        XCTAssertEqual(page.items[0].name, "root")
        XCTAssertEqual(page.items[0].gid, 0)
        XCTAssertTrue(page.items[0].members.isEmpty)
        XCTAssertEqual(page.items[1].name, "daemon")
        XCTAssertEqual(page.items[1].gid, 1)
    }

    // MARK: - Docker

    func testDockerInfoDecodes() throws {
        let info = try Fixtures.decode(DockerInfo.self, from: "docker_info.json")

        XCTAssertEqual(info.version, "29.4.3")
        XCTAssertEqual(info.apiVersion, "1.43")
        XCTAssertEqual(info.rootDir, "/var/lib/docker")
        XCTAssertEqual(info.storageDriver, "overlayfs")
        XCTAssertEqual(info.containersTotal, 1)
        XCTAssertEqual(info.containersRunning, 1)
        XCTAssertEqual(info.containersStopped, 0)
        XCTAssertEqual(info.containersPaused, 0)
        XCTAssertEqual(info.images, 1)
        XCTAssertEqual(info.cpus, 2)
        XCTAssertEqual(info.memoryBytes, 8_413_380_608)
        XCTAssertEqual(info.cgroupVersion, "1")
        XCTAssertEqual(info.liveRestore, false)
        XCTAssertEqual(info.warnings?.count, 2)
        XCTAssertEqual(info.warnings?.last, "WARNING: IPv4 forwarding is disabled")
    }

    func testDockerContainersDecode() throws {
        let list = try Fixtures.decode(DockerContainerList.self, from: "docker_containers.json")

        XCTAssertEqual(list.total, 1)
        XCTAssertEqual(list.running, 1)
        XCTAssertEqual(list.statsSampled, 0)
        XCTAssertEqual(list.statsTruncated, false)

        let container = list.items[0]
        XCTAssertEqual(container.id, "cce11a5e40c3f8e1a3490ad6ce868b39df54cf87bcaedbb8d4360dc1a448b1f3")
        XCTAssertEqual(container.shortID, "cce11a5e40c3")
        XCTAssertEqual(container.name, "sos-fixture")
        XCTAssertEqual(container.image, "serveros-test:base")
        XCTAssertEqual(
            container.imageID,
            "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950"
        )
        XCTAssertEqual(container.state, "running")
        XCTAssertEqual(container.status, "Up 3 seconds")
        XCTAssertTrue(container.isRunning)
        XCTAssertFalse(container.isStopped)
        XCTAssertNil(container.health)
        XCTAssertFalse(container.isUnhealthy)
        XCTAssertEqual(container.createdAt, 1_789_210_501)
        XCTAssertNil(container.startedAt)
        XCTAssertNil(container.restartCount)
        XCTAssertEqual(container.ports.count, 0)
        XCTAssertEqual(container.networks, ["bridge"])
        XCTAssertNil(container.cpuPercent)
        XCTAssertNil(container.memoryBytes)

        // Docker labels are a free-form map whose keys contain dots. This is
        // the exact case `.convertFromSnakeCase` would mangle, which is why the
        // models spell their `CodingKeys` out.
        XCTAssertEqual(container.labels?["com.docker.compose.project"], "estatify")
        XCTAssertEqual(container.labels?["com.docker.compose.service"], "api")
        XCTAssertEqual(container.composeProject, "estatify")
        XCTAssertEqual(container.composeService, "api")
        // Compose service names read better than generated container names.
        XCTAssertEqual(container.displayName, "api")
    }

    func testDockerInspectDecodes() throws {
        let detail = try Fixtures.decode(DockerContainerDetail.self, from: "docker_inspect.json")

        XCTAssertEqual(detail.shortID, "cce11a5e40c3")
        XCTAssertEqual(detail.name, "sos-fixture")
        XCTAssertEqual(detail.state, "running")
        XCTAssertTrue(detail.isRunning)
        XCTAssertEqual(detail.status, "Up")
        XCTAssertEqual(detail.createdAt, 1_789_210_501)
        XCTAssertEqual(detail.startedAt, 1_789_210_501)
        XCTAssertNil(detail.finishedAt)
        XCTAssertEqual(detail.restartCount, 0)
        XCTAssertEqual(detail.exitCode, 0)
        XCTAssertEqual(detail.tty, false)
        XCTAssertEqual(detail.platform, "linux")
        XCTAssertNil(detail.workingDir)
        XCTAssertNil(detail.user)
        XCTAssertNil(detail.healthCheck)

        XCTAssertEqual(detail.command?.count, 3)
        XCTAssertEqual(detail.command?.first, "sh")
        XCTAssertNotNil(detail.entrypoint)
        XCTAssertEqual(detail.entrypoint?.count, 0)

        XCTAssertEqual(detail.networks?.count, 1)
        XCTAssertEqual(detail.networks?.first?.name, "bridge")
        XCTAssertNil(detail.networks?.first?.ipAddress)

        XCTAssertEqual(detail.restartPolicy?.name, "no")
        XCTAssertEqual(detail.restartPolicy?.maxRetryCount, 0)
        XCTAssertEqual(detail.restartPolicy?.described, "Never")
        XCTAssertEqual(detail.mounts?.count, 0)

        // The masked-environment contract: value is nil exactly when masked is
        // true, so the UI can draw a deliberate "hidden" affordance instead of
        // an empty string that looks like a bug.
        let environment = try XCTUnwrap(detail.env)
        XCTAssertEqual(environment.count, 3)

        let nodeEnv = try XCTUnwrap(environment.first { $0.key == "NODE_ENV" })
        XCTAssertEqual(nodeEnv.value, "production")
        XCTAssertFalse(nodeEnv.masked)

        let databaseURL = try XCTUnwrap(environment.first { $0.key == "DATABASE_URL" })
        XCTAssertNil(databaseURL.value)
        XCTAssertTrue(databaseURL.masked)

        let port = try XCTUnwrap(environment.first { $0.key == "PORT" })
        XCTAssertEqual(port.value, "3000")
        XCTAssertFalse(port.masked)
    }

    func testDockerImagesDecode() throws {
        let page = try Fixtures.decode(AgentCollection<DockerImage>.self, from: "docker_images.json")

        XCTAssertEqual(page.total, 1)
        let image = page.items[0]
        XCTAssertEqual(image.shortID, "9a0cea180511")
        XCTAssertEqual(image.repoTags, ["serveros-test:base"])
        XCTAssertEqual(image.repository, "serveros-test")
        XCTAssertEqual(image.tag, "base")
        XCTAssertEqual(image.sizeBytes, 3_857_897)
        XCTAssertEqual(image.createdAt, 1_789_200_756)
        XCTAssertFalse(image.dangling)
        XCTAssertNil(image.containers)
        XCTAssertEqual(image.displayName, "serveros-test:base")
    }

    func testDockerVolumesDecode() throws {
        let page = try Fixtures.decode(AgentCollection<DockerVolume>.self, from: "docker_volumes.json")

        XCTAssertEqual(page.total, 1)
        let volume = page.items[0]
        XCTAssertEqual(volume.name, "serveros-testvol")
        XCTAssertEqual(volume.driver, "local")
        XCTAssertEqual(volume.mountpoint, "/var/lib/docker/volumes/serveros-testvol/_data")
        XCTAssertEqual(volume.createdAt, 1_789_200_830)
        XCTAssertNotNil(volume.labels)
        XCTAssertEqual(volume.labels?.count, 0)
        XCTAssertNil(volume.sizeBytes)
        XCTAssertEqual(volume.inUse, false)
    }

    func testDockerNetworksDecode() throws {
        let page = try Fixtures.decode(AgentCollection<DockerNetwork>.self, from: "docker_networks.json")

        XCTAssertEqual(page.total, 3)

        let none = page.items[0]
        XCTAssertEqual(none.name, "none")
        XCTAssertEqual(none.driver, "null")
        XCTAssertEqual(none.scope, "local")
        XCTAssertFalse(none.`internal`)
        XCTAssertNil(none.subnet)
        XCTAssertNil(none.gateway)
        XCTAssertEqual(none.containerCount, 0)

        let bridge = page.items[2]
        XCTAssertEqual(bridge.name, "serveros-testnet")
        XCTAssertEqual(bridge.driver, "bridge")
        XCTAssertEqual(bridge.subnet, "172.17.0.0/16")
        XCTAssertEqual(bridge.gateway, "172.17.0.1")
    }

    // MARK: - Projects

    func testProjectsDecode() throws {
        let list = try Fixtures.decode(ProjectList.self, from: "projects.json")

        XCTAssertEqual(list.total, 1)
        XCTAssertEqual(list.running, 1)
        XCTAssertEqual(list.degraded, 0)

        let project = list.items[0]
        XCTAssertEqual(project.name, "estatify")
        XCTAssertEqual(project.serviceCount, 1)
        XCTAssertEqual(project.containerCount, 1)
        XCTAssertEqual(project.running, 1)
        XCTAssertEqual(project.state, "running")
        XCTAssertTrue(project.isFullyRunning)
        XCTAssertFalse(project.isPartiallyRunning)
        XCTAssertNil(project.workingDir)
        XCTAssertEqual(project.services, ["api"])
        XCTAssertEqual(project.containers?.count, 1)
        XCTAssertEqual(project.containers?.first?.composeService, "api")
    }

    // MARK: - Databases

    func testDatabaseInstancesDecode() throws {
        let page = try Fixtures.decode(AgentCollection<DatabaseInstance>.self, from: "databases.json")

        XCTAssertEqual(page.total, 1)
        XCTAssertEqual(page.items[0].port, 55_432)
        XCTAssertEqual(page.items[0].socketDir, "/tmp")
        XCTAssertTrue(page.items[0].reachable)
    }

    func testPostgresOverviewDecodes() throws {
        let overview = try Fixtures.decode(PostgresOverview.self, from: "pg_overview.json")

        XCTAssertEqual(overview.version, "16.13")
        XCTAssertEqual(overview.versionNum, 160_013)
        XCTAssertEqual(overview.uptimeSeconds, 8_320)
        XCTAssertEqual(overview.startedAt, 1_789_202_185)
        XCTAssertEqual(overview.dataDirectory, "/tmp/pgdata")
        XCTAssertEqual(overview.maxConnections, 100)
        XCTAssertEqual(overview.currentConnections, 6)
        XCTAssertEqual(overview.connectionUsagePercent ?? 0, 6.0, accuracy: 0.0001)
        XCTAssertEqual(overview.databaseCount, 3)
        XCTAssertEqual(overview.totalSizeBytes, 23_018_045)
        XCTAssertEqual(overview.cacheHitRatio ?? 0, 99.4, accuracy: 0.0001)
        XCTAssertEqual(overview.transactionsCommitted, 2_356)
        XCTAssertEqual(overview.transactionsRolledBack, 10)
        XCTAssertEqual(overview.deadlocks, 0)
        XCTAssertEqual(overview.health, "healthy")
        XCTAssertNil(overview.healthReason)
    }

    func testPostgresDatabasesDecode() throws {
        let page = try Fixtures.decode(AgentCollection<PostgresDatabase>.self, from: "pg_databases.json")

        XCTAssertEqual(page.total, 3)

        let first = page.items[0]
        XCTAssertEqual(first.name, "postgres")
        XCTAssertEqual(first.owner, "serveros")
        XCTAssertEqual(first.sizeBytes, 7_748_631)
        XCTAssertEqual(first.encoding, "UTF8")
        XCTAssertEqual(first.collation, "C.UTF-8")
        XCTAssertEqual(first.connectionLimit, -1)
        XCTAssertEqual(first.isTemplate, false)
        XCTAssertNil(first.tableCount)

        XCTAssertEqual(page.items[1].name, "template0")
        XCTAssertEqual(page.items[1].isTemplate, true)
    }

    func testPostgresConnectionsDecode() throws {
        let page = try Fixtures.decode(AgentCollection<PostgresConnection>.self, from: "pg_connections.json")

        XCTAssertEqual(page.total, 6)

        let first = page.items[0]
        XCTAssertEqual(first.pid, 18_682)
        XCTAssertNil(first.user)
        XCTAssertNil(first.database)
        XCTAssertNil(first.clientAddr)
        XCTAssertEqual(first.applicationName, "")
        XCTAssertNil(first.state)
        XCTAssertEqual(first.waitEventType, "Activity")
        XCTAssertEqual(first.backendType, "checkpointer")
        // Statement text is omitted unless an operator explicitly asked for it
        // and has admin scope.
        XCTAssertNil(first.queryPreview)

        XCTAssertEqual(page.items[1].backendType, "background writer")
    }

    func testPostgresRolesDecode() throws {
        let page = try Fixtures.decode(AgentCollection<PostgresRole>.self, from: "pg_roles.json")

        XCTAssertEqual(page.total, 17)

        let first = page.items[0]
        XCTAssertEqual(first.name, "md5user")
        XCTAssertEqual(first.isSuperuser, false)
        XCTAssertEqual(first.canCreateDB, false)
        XCTAssertEqual(first.canCreateRole, false)
        XCTAssertEqual(first.canLogin, true)
        XCTAssertEqual(first.isReplication, false)
        XCTAssertEqual(first.bypassesRLS, false)
        // PostgreSQL reports "no limit" as -1; the UI shows "Unlimited".
        XCTAssertEqual(first.connectionLimit, -1)
        XCTAssertTrue(first.hasUnlimitedConnections)
        XCTAssertNil(first.validUntil)
        XCTAssertTrue(first.privileges.isEmpty)

        let checkpoint = page.items[1]
        XCTAssertEqual(checkpoint.name, "pg_checkpoint")
        XCTAssertEqual(checkpoint.canLogin, false)
        XCTAssertEqual(checkpoint.privileges, ["Cannot log in"])
    }

    // MARK: - Files

    func testFileListingDecodes() throws {
        let listing = try Fixtures.decode(DirectoryListing.self, from: "files_list.json")

        XCTAssertEqual(listing.path, "/etc")
        XCTAssertEqual(listing.parent, "/")
        XCTAssertEqual(listing.total, 161)
        XCTAssertEqual(listing.truncated, true)
        XCTAssertEqual(listing.entries.count, 8)

        let first = listing.entries[0]
        XCTAssertEqual(first.name, "alternatives")
        XCTAssertEqual(first.path, "/etc/alternatives")
        XCTAssertEqual(first.kind, "directory")
        XCTAssertTrue(first.isDirectory)
        XCTAssertFalse(first.isRegularFile)
        XCTAssertEqual(first.sizeBytes, 12_288)
        XCTAssertEqual(first.modifiedAt, 1_778_273_048)
        XCTAssertEqual(first.mode, "0755")
        XCTAssertEqual(first.modeOctal, 493)
        XCTAssertEqual(first.owner, "root")
        XCTAssertEqual(first.group, "root")
        XCTAssertEqual(first.uid, 0)
        XCTAssertEqual(first.gid, 0)
        XCTAssertFalse(first.isSymlink)
        XCTAssertNil(first.symlinkTarget)
        XCTAssertEqual(first.isReadable, true)
        XCTAssertEqual(first.isWritable, true)
        XCTAssertNil(first.`extension`)
        XCTAssertEqual(first.isText, false)
        XCTAssertFalse(first.isEditable)
    }

    func testFileStatDecodes() throws {
        let entry = try Fixtures.decode(FileEntry.self, from: "files_stat.json")

        XCTAssertEqual(entry.name, "hosts")
        XCTAssertEqual(entry.path, "/etc/hosts")
        XCTAssertEqual(entry.kind, "file")
        XCTAssertTrue(entry.isRegularFile)
        XCTAssertEqual(entry.sizeBytes, 49)
        XCTAssertEqual(entry.modifiedAt, 1_789_198_633)
        XCTAssertEqual(entry.mode, "0644")
        XCTAssertEqual(entry.modeOctal, 420)
        XCTAssertEqual(entry.isText, true)
        // Readable, writable, text and a regular file: double-clicking it opens
        // the editor.
        XCTAssertTrue(entry.isEditable)
        XCTAssertEqual(entry.id, "/etc/hosts")
    }

    func testFileReadDecodes() throws {
        let file = try Fixtures.decode(TextFileContents.self, from: "files_read.json")

        XCTAssertEqual(file.path, "/etc/hostname")
        XCTAssertEqual(file.content, "vm\n")
        XCTAssertEqual(file.encoding, "utf-8")
        XCTAssertEqual(file.lineCount, 1)
        XCTAssertEqual(file.sizeBytes, 3)
        XCTAssertFalse(file.truncated)
        XCTAssertEqual(file.lineEnding, "lf")
        XCTAssertEqual(file.readonly, false)
    }

    // MARK: - Errors

    func testDeniedErrorDecodesAndBecomesReadable() throws {
        let wire = try Fixtures.decode(WireError.self, from: "error_denied.json")

        XCTAssertEqual(wire.error.code, "denied")
        XCTAssertTrue(wire.error.message.hasPrefix("/etc/shadow is inside"))
        XCTAssertNil(wire.error.detail)

        let error = ServerOSError.from(wire: wire, status: 403)
        XCTAssertEqual(error.code, "denied")
        XCTAssertEqual(error.headline, wire.error.message)
        XCTAssertEqual(error.causes, ["ServerOS refuses to touch this path to protect the server."])
        XCTAssertFalse(error.isRetryable)
        XCTAssertFalse(error.needsFreshCredential)
    }

    func testNotFoundErrorDecodesAndBecomesReadable() throws {
        let wire = try Fixtures.decode(WireError.self, from: "error_notfound.json")

        XCTAssertEqual(wire.error.code, "not_found")
        XCTAssertEqual(wire.error.message, "No such endpoint on this agent")

        let error = ServerOSError.from(wire: wire, status: 404)
        XCTAssertEqual(error.code, "not_found")
        XCTAssertTrue(error.isRetryable)
    }

    func testAbsentSubsystemDecodesAsACalmAnswer() throws {
        // `services.json` is not a Services listing: this host has no systemd,
        // and the agent answered 503 with a sentence. A missing capability is
        // not a failure and must not be rendered as one.
        let wire = try Fixtures.decode(WireError.self, from: "services.json")

        XCTAssertEqual(wire.error.code, "subsystem_unavailable")
        XCTAssertEqual(wire.error.message, "Service management is not available on this server.")
        XCTAssertEqual(
            wire.error.detail,
            "systemd is not this host's init system, or its bus is unreachable and systemctl is absent"
        )

        let error = ServerOSError.from(wire: wire, status: 503)
        XCTAssertEqual(error.code, "subsystem_unavailable")
        XCTAssertEqual(error.headline, "Service management is not available on this server.")
        XCTAssertEqual(error.causes, [])
        XCTAssertEqual(error.technical, wire.error.detail)
        XCTAssertFalse(error.isRetryable)
    }

    func testAuthExpiredAsksForASilentRetry() throws {
        // Not a fixture — the agent only emits this under an expired token —
        // but it is the one error code whose handling changes behaviour rather
        // than copy, so it is asserted alongside the captured ones.
        let json = Data(#"{"error":{"code":"auth_expired","message":"The credential has expired."}}"#.utf8)
        let wire = try JSONDecoder().decode(WireError.self, from: json)
        let error = ServerOSError.from(wire: wire, status: 401)

        XCTAssertEqual(error.code, "auth_expired")
        XCTAssertTrue(error.isRetryable)
        XCTAssertTrue(error.needsFreshCredential)
    }

    // MARK: - Stream frames

    func testStreamWelcomeDecodes() throws {
        // The welcome frame is not captured in `fixtures/` because it only
        // exists on a socket, so its shape is pinned here against
        // `agent/crates/agent/src/stream.rs`.
        let json = Data("""
        {"type":"welcome","agent_version":"0.1.0","api_version":"1",
         "server_id":"srv_563016eaa2ea5baa","channels":["metrics","docker","services","activity"],
         "metrics_interval_ms":2000,
         "capabilities":{"metrics":true,"processes":true,"users":true,"files":true,"logs":true,
                         "docker":true,"docker_api_version":"1.43","services":false,
                         "journal":false,"postgres":true}}
        """.utf8)

        let welcome = try JSONDecoder().decode(StreamWelcome.self, from: json)
        XCTAssertEqual(welcome.agentVersion, "0.1.0")
        XCTAssertEqual(welcome.apiVersion, "1")
        XCTAssertEqual(welcome.serverID, "srv_563016eaa2ea5baa")
        XCTAssertEqual(welcome.channels, ["metrics", "docker", "services", "activity"])
        XCTAssertEqual(welcome.metricsIntervalMs, 2_000)
        XCTAssertTrue(welcome.capabilities.postgres)
        XCTAssertFalse(welcome.capabilities.services)
    }
}
