//  AgentClient.swift
//  ServerOS
//
//  The HTTP half of talking to one server's agent.
//
//  # Why `localhost` and never `127.0.0.1`
//
//  The agent binds loopback on the *server* and is reached through an SSH
//  tunnel, so every URL here is `http://localhost:<local port>`. Plain HTTP is
//  correct — the transport security is the SSH tunnel, and wrapping TLS around
//  a tunnelled loopback socket would add a certificate to manage and no safety.
//
//  The hostname is not a style choice. From macOS 14 — this app's deployment
//  target — App Transport Security no longer allows cleartext connections to IP
//  *literals* by default, so `http://127.0.0.1:8723` fails with
//  `NSURLErrorAppTransportSecurityRequiresSecureConnection` (-1022) and no
//  amount of retrying helps. `localhost` is an unqualified domain rather than
//  an IP literal and is allowed with no Info.plist exception at all. Building
//  the URL from `AgentClient.loopbackURL(port:)` is what keeps that from being
//  re-learned the hard way.
//
//  # One token per request
//
//  `request` mints a token inside every attempt and never caches one. The agent
//  remembers recent token ids and refuses a repeat, so a cached token would
//  work exactly once and then fail as `auth_replayed`. The retry path mints
//  again for the same reason.
//
//  # Cancellation
//
//  Every call goes through `URLSession.data(for:)`, which honours the
//  surrounding `Task`'s cancellation and surfaces it as `URLError.cancelled`.
//  That becomes `ServerOSError` code `cancelled`, which the UI knows to swallow
//  rather than show. Navigating away from a screen therefore stops its work
//  rather than leaving it to finish into a view that has gone.

import Foundation

/// Talks to one server's agent over its tunnelled loopback port.
public actor AgentClient: AgentAPI {

    /// Enough for a listing through a tunnel on a slow link; short enough that
    /// a dead agent is reported rather than spun on.
    public static let defaultTimeout: TimeInterval = 15

    /// File reads, writes and uploads get longer — they are bounded by disk and
    /// bandwidth rather than by the server's responsiveness.
    public static let fileTimeout: TimeInterval = 60

    /// The server's display name, used only to make error copy nameable.
    public let serverName: String

    /// What this server reported it can do, as of the last `health()` or
    /// `fetchCapabilities()`. `.none` until one of those has answered — the
    /// sidebar draws nothing rather than guessing.
    public private(set) var capabilities: AgentCapabilities = .none

    private let baseURL: URL
    private let minter: AgentTokenMinter
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    /// Create a client for one server.
    ///
    /// - Parameters:
    ///   - baseURL: Always `http://localhost:<local tunnel port>`. Use
    ///     ``loopbackURL(port:)`` rather than assembling it by hand.
    ///   - minter: Holds the server's enrollment secret.
    ///   - serverName: For error copy: "ServerOS couldn't reach the agent on Production."
    ///   - session: Injectable so tests can stub the transport.
    public init(baseURL: URL, minter: AgentTokenMinter, serverName: String, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.minter = minter
        self.serverName = serverName
        self.session = session
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    /// `http://localhost:<port>` — the only shape of base URL that works. See
    /// the file comment for why the hostname cannot be `127.0.0.1`.
    public static func loopbackURL(port: Int) -> URL {
        var components = URLComponents()
        components.scheme = "http"
        components.host = "localhost"
        components.port = min(max(port, 1), 65_535)
        if let url = components.url {
            return url
        }
        // Unreachable: scheme + host + port always composes. Returning a URL
        // that cannot resolve keeps this non-failing without a force unwrap —
        // every request built on it fails as an ordinary transport error, which
        // the UI already knows how to show.
        return URL(fileURLWithPath: "/dev/null")
    }

    // MARK: - Meta

    public func health() async throws -> AgentHealth {
        // `/v1/health` is the one unauthenticated route, but a token is sent
        // anyway: it costs nothing and means every request in the app has
        // exactly one shape.
        let result: AgentHealth = try await request(.get, "/v1/health")
        capabilities = result.capabilities
        return result
    }

    public func fetchCapabilities() async throws -> AgentCapabilities {
        let result: AgentCapabilities = try await request(.get, "/v1/capabilities")
        capabilities = result
        return result
    }

    public func system() async throws -> SystemInfo {
        try await request(.get, "/v1/system")
    }

    public func metrics() async throws -> Metrics {
        try await request(.get, "/v1/metrics")
    }

    // Note on defaults: methods that the `AgentAPI` protocol extension also
    // offers a shorthand for declare no default arguments here. Two overloads
    // that both match a bare `activity()` — one concrete with defaults, one
    // from the extension — is exactly the ambiguity that makes call sites
    // fragile, so the extension is the single place defaults live.
    public func activity(limit: Int, since: Int64?) async throws -> [ActivityEvent] {
        var query: [URLQueryItem] = [URLQueryItem(name: "limit", value: String(limit))]
        if let since {
            query.append(URLQueryItem(name: "since", value: String(since)))
        }
        let page: AgentCollection<ActivityEvent> = try await request(.get, "/v1/activity", query: query)
        return page.items
    }

    // MARK: - Processes

    public func processes(sort: ProcessSort, limit: Int, search: String?) async throws -> ProcessList {
        var query: [URLQueryItem] = [
            URLQueryItem(name: "sort", value: sort.rawValue),
            URLQueryItem(name: "limit", value: String(limit)),
        ]
        if let search, !search.isEmpty {
            query.append(URLQueryItem(name: "search", value: search))
        }
        return try await request(.get, "/v1/processes", query: query)
    }

    public func signalProcess(pid: Int32, signal: ProcessSignal) async throws {
        let path = "/v1/processes/\(AgentClient.escape(String(pid)))/signal"
        let body = try encodeBody(SignalBody(signal: signal.rawValue), endpoint: path)
        try await requestVoid(.post, path, body: body, scopes: [.read, .write])
    }

    // MARK: - Users

    public func users(includeSystem: Bool) async throws -> UserList {
        let query = [URLQueryItem(name: "include_system", value: includeSystem ? "true" : "false")]
        return try await request(.get, "/v1/users", query: query)
    }

    public func groups() async throws -> [LinuxGroup] {
        let page: AgentCollection<LinuxGroup> = try await request(.get, "/v1/groups")
        return page.items
    }

    public func user(named name: String) async throws -> LinuxUser {
        try await request(.get, "/v1/users/\(AgentClient.escape(name))")
    }

    public func createUser(_ newUser: NewUser) async throws -> LinuxUser {
        let body = try encodeBody(newUser, endpoint: "/v1/users")
        return try await request(.post, "/v1/users", body: body, scopes: [.read, .write])
    }

    public func updateUser(named name: String, changes: UserChanges) async throws -> LinuxUser {
        let path = "/v1/users/\(AgentClient.escape(name))"
        let body = try encodeBody(changes, endpoint: path)
        return try await request(.patch, path, body: body, scopes: [.read, .write])
    }

    public func deleteUser(named name: String, removeHome: Bool = false) async throws {
        let query = [URLQueryItem(name: "remove_home", value: removeHome ? "true" : "false")]
        try await requestVoid(
            .delete,
            "/v1/users/\(AgentClient.escape(name))",
            query: query,
            scopes: [.read, .write, .admin]
        )
    }

    public func sshKeys(forUser name: String) async throws -> [SSHKeyEntry] {
        let page: AgentCollection<SSHKeyEntry> = try await request(
            .get,
            "/v1/users/\(AgentClient.escape(name))/keys"
        )
        return page.items
    }

    public func addSSHKey(forUser name: String, publicKey: String) async throws {
        let path = "/v1/users/\(AgentClient.escape(name))/keys"
        let body = try encodeBody(SSHKeyBody(key: publicKey), endpoint: path)
        try await requestVoid(.post, path, body: body, scopes: [.read, .write])
    }

    public func removeSSHKey(forUser name: String, fingerprint: String) async throws {
        let path = "/v1/users/\(AgentClient.escape(name))/keys/\(AgentClient.escape(fingerprint))"
        try await requestVoid(.delete, path, scopes: [.read, .write])
    }

    // MARK: - Services

    public func services(type: String?) async throws -> [ServiceUnit] {
        var query: [URLQueryItem] = []
        if let type, !type.isEmpty {
            query.append(URLQueryItem(name: "type", value: type))
        }
        let page: AgentCollection<ServiceUnit> = try await request(.get, "/v1/services", query: query)
        return page.items
    }

    public func service(unit: String) async throws -> ServiceUnitDetail {
        try await request(.get, "/v1/services/\(AgentClient.escape(unit))")
    }

    public func performServiceAction(_ action: ServiceAction, unit: String) async throws {
        // The agent answers with the re-read unit so a client can render the
        // new state without polling. This ignores it: the screens that act on a
        // service are already watching the `services` stream channel, and
        // decoding a body two different ways depending on whether systemd could
        // be re-read is a worse trade than one refresh.
        let path = "/v1/services/\(AgentClient.escape(unit))/\(action.pathComponent)"
        try await requestVoid(.post, path, scopes: action.requiredScopes)
    }

    // MARK: - Docker

    public func dockerInfo() async throws -> DockerInfo {
        try await request(.get, "/v1/docker")
    }

    public func containers(all: Bool, stats: Bool) async throws -> DockerContainerList {
        let query = [
            URLQueryItem(name: "all", value: all ? "true" : "false"),
            URLQueryItem(name: "stats", value: stats ? "true" : "false"),
        ]
        return try await request(.get, "/v1/docker/containers", query: query)
    }

    public func container(id: String, revealEnvironment: Bool) async throws -> DockerContainerDetail {
        let query = [URLQueryItem(name: "reveal", value: revealEnvironment ? "true" : "false")]
        // Asking to unmask environment values is a privileged read and is
        // audited on the server, so the token says so. Without admin the agent
        // ignores the flag and returns masked values rather than failing.
        let scopes: [AgentScope] = revealEnvironment ? [.read, .write, .admin] : [.read]
        return try await request(
            .get,
            "/v1/docker/containers/\(AgentClient.escape(id))",
            query: query,
            scopes: scopes
        )
    }

    public func containerStats(id: String) async throws -> DockerStats {
        try await request(.get, "/v1/docker/containers/\(AgentClient.escape(id))/stats")
    }

    public func containerLogs(
        id: String,
        tail: Int,
        since: Int64?,
        timestamps: Bool
    ) async throws -> [LogLine] {
        var query: [URLQueryItem] = [
            URLQueryItem(name: "tail", value: String(tail)),
            URLQueryItem(name: "timestamps", value: timestamps ? "true" : "false"),
        ]
        if let since {
            query.append(URLQueryItem(name: "since", value: String(since)))
        }
        let page: AgentCollection<LogLine> = try await request(
            .get,
            "/v1/docker/containers/\(AgentClient.escape(id))/logs",
            query: query
        )
        return page.items
    }

    public func performContainerAction(
        _ action: ContainerAction,
        id: String,
        graceSeconds: Int? = nil
    ) async throws {
        var query: [URLQueryItem] = []
        if let graceSeconds {
            query.append(URLQueryItem(name: "t", value: String(graceSeconds)))
        }
        let path = "/v1/docker/containers/\(AgentClient.escape(id))/\(action.pathComponent)"
        try await requestVoid(.post, path, query: query, scopes: [.read, .write])
    }

    public func removeContainer(id: String, force: Bool = false, removeVolumes: Bool = false) async throws {
        let query = [
            URLQueryItem(name: "force", value: force ? "true" : "false"),
            URLQueryItem(name: "volumes", value: removeVolumes ? "true" : "false"),
        ]
        try await requestVoid(
            .delete,
            "/v1/docker/containers/\(AgentClient.escape(id))",
            query: query,
            scopes: [.read, .write, .admin]
        )
    }

    public func images() async throws -> [DockerImage] {
        let page: AgentCollection<DockerImage> = try await request(.get, "/v1/docker/images")
        return page.items
    }

    public func volumes() async throws -> [DockerVolume] {
        let page: AgentCollection<DockerVolume> = try await request(.get, "/v1/docker/volumes")
        return page.items
    }

    public func networks() async throws -> [DockerNetwork] {
        let page: AgentCollection<DockerNetwork> = try await request(.get, "/v1/docker/networks")
        return page.items
    }

    // MARK: - Projects

    public func projects() async throws -> ProjectList {
        try await request(.get, "/v1/projects")
    }

    public func project(named name: String) async throws -> Project {
        try await request(.get, "/v1/projects/\(AgentClient.escape(name))")
    }

    // MARK: - Databases

    public func databaseInstances() async throws -> [DatabaseInstance] {
        let page: AgentCollection<DatabaseInstance> = try await request(.get, "/v1/databases")
        return page.items
    }

    public func postgresOverview() async throws -> PostgresOverview {
        try await request(.get, "/v1/databases/postgres")
    }

    public func postgresDatabases() async throws -> [PostgresDatabase] {
        let page: AgentCollection<PostgresDatabase> = try await request(
            .get,
            "/v1/databases/postgres/databases"
        )
        return page.items
    }

    public func postgresTables(database: String? = nil) async throws -> [PostgresTable] {
        var query: [URLQueryItem] = []
        if let database, !database.isEmpty {
            query.append(URLQueryItem(name: "database", value: database))
        }
        let page: AgentCollection<PostgresTable> = try await request(
            .get,
            "/v1/databases/postgres/tables",
            query: query
        )
        return page.items
    }

    public func postgresConnections(includeQueryText: Bool = false) async throws -> [PostgresConnection] {
        let query = [URLQueryItem(name: "include_query", value: includeQueryText ? "true" : "false")]
        // Statement text can contain personal data and credentials, so the
        // agent gates it on admin. As with revealing container environment, a
        // caller without it gets the answer with the text omitted.
        let scopes: [AgentScope] = includeQueryText ? [.read, .write, .admin] : [.read]
        let page: AgentCollection<PostgresConnection> = try await request(
            .get,
            "/v1/databases/postgres/connections",
            query: query,
            scopes: scopes
        )
        return page.items
    }

    public func postgresRoles() async throws -> [PostgresRole] {
        let page: AgentCollection<PostgresRole> = try await request(.get, "/v1/databases/postgres/roles")
        return page.items
    }

    // MARK: - Logs

    public func fileLog(
        path: String,
        lines: Int = 200,
        since: Int64? = nil,
        filter: String? = nil,
        isRegex: Bool = false
    ) async throws -> LogBatch {
        try await request(
            .get,
            "/v1/logs/file",
            query: AgentClient.logQuery(
                extra: [URLQueryItem(name: "path", value: path)],
                lines: lines,
                since: since,
                filter: filter,
                isRegex: isRegex
            ),
            timeout: AgentClient.fileTimeout
        )
    }

    public func journal(
        unit: String? = nil,
        lines: Int = 200,
        since: Int64? = nil,
        filter: String? = nil,
        isRegex: Bool = false
    ) async throws -> LogBatch {
        var extra: [URLQueryItem] = []
        if let unit, !unit.isEmpty {
            extra.append(URLQueryItem(name: "unit", value: unit))
        }
        return try await request(
            .get,
            "/v1/logs/journal",
            query: AgentClient.logQuery(
                extra: extra,
                lines: lines,
                since: since,
                filter: filter,
                isRegex: isRegex
            ),
            timeout: AgentClient.fileTimeout
        )
    }

    // MARK: - Files

    public func listDirectory(
        path: String,
        showHidden: Bool,
        sort: FileSort,
        limit: Int,
        offset: Int
    ) async throws -> DirectoryListing {
        let query = [
            URLQueryItem(name: "path", value: path),
            URLQueryItem(name: "show_hidden", value: showHidden ? "true" : "false"),
            URLQueryItem(name: "sort", value: sort.rawValue),
            // `limit=0` means "the agent's own default", which is what an
            // ordinary directory listing wants.
            URLQueryItem(name: "limit", value: String(limit)),
            URLQueryItem(name: "offset", value: String(offset)),
        ]
        return try await request(.get, "/v1/files", query: query, timeout: AgentClient.fileTimeout)
    }

    public func stat(path: String) async throws -> FileEntry {
        try await request(.get, "/v1/files/stat", query: [URLQueryItem(name: "path", value: path)])
    }

    public func readTextFile(path: String) async throws -> TextFileContents {
        try await request(
            .get,
            "/v1/files/read",
            query: [URLQueryItem(name: "path", value: path)],
            timeout: AgentClient.fileTimeout
        )
    }

    public func downloadFile(path: String) async throws -> Data {
        try await rawData("/v1/files/download", query: [URLQueryItem(name: "path", value: path)])
    }

    public func writeTextFile(path: String, contents: String) async throws -> FileEntry {
        // The body is the file, verbatim: no JSON wrapper and no base64, so a
        // 3 MB config costs 3 MB rather than 4.
        try await request(
            .put,
            "/v1/files/write",
            query: [URLQueryItem(name: "path", value: path)],
            body: Data(contents.utf8),
            contentType: "text/plain; charset=utf-8",
            scopes: [.read, .write],
            timeout: AgentClient.fileTimeout
        )
    }

    public func createDirectory(path: String) async throws -> FileEntry {
        let body = try encodeBody(PathBody(path: path), endpoint: "/v1/files/directory")
        return try await request(.post, "/v1/files/directory", body: body, scopes: [.read, .write])
    }

    public func move(from: String, to: String) async throws -> FileEntry {
        let body = try encodeBody(RenameBody(from: from, to: to), endpoint: "/v1/files/rename")
        return try await request(.post, "/v1/files/rename", body: body, scopes: [.read, .write])
    }

    public func changeMode(path: String, mode: String) async throws -> FileEntry {
        // Permissions are the mechanism every other permission rests on, so the
        // agent guards this with admin rather than write.
        let body = try encodeBody(ChmodBody(path: path, mode: mode), endpoint: "/v1/files/chmod")
        return try await request(.post, "/v1/files/chmod", body: body, scopes: [.read, .write, .admin])
    }

    public func deleteFile(path: String, recursive: Bool = false) async throws -> FileDeletion {
        let query = [
            URLQueryItem(name: "path", value: path),
            URLQueryItem(name: "recursive", value: recursive ? "true" : "false"),
        ]
        return try await request(
            .delete,
            "/v1/files",
            query: query,
            scopes: [.read, .write],
            timeout: AgentClient.fileTimeout
        )
    }

    public func uploadFile(path: String, contents: Data, overwrite: Bool = false) async throws -> FileEntry {
        let query = [
            URLQueryItem(name: "path", value: path),
            URLQueryItem(name: "overwrite", value: overwrite ? "true" : "false"),
        ]
        return try await request(
            .post,
            "/v1/files/upload",
            query: query,
            body: contents,
            contentType: "application/octet-stream",
            scopes: [.read, .write],
            timeout: AgentClient.fileTimeout
        )
    }

    // MARK: - The one request path

    /// Send a request and decode its body.
    ///
    /// Everything above funnels through here, so authentication, the retry
    /// rule, error translation and decoding are decided once.
    private func request<T: Decodable>(
        _ method: AgentHTTPMethod,
        _ path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        contentType: String? = nil,
        scopes: [AgentScope] = [.read],
        timeout: TimeInterval = AgentClient.defaultTimeout
    ) async throws -> T {
        let data = try await send(
            method,
            path,
            query: query,
            body: body,
            contentType: contentType,
            scopes: scopes,
            timeout: timeout
        )
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw ServerOSError.decoding(error, endpoint: path)
        }
    }

    /// Send a request whose body the app does not need.
    ///
    /// Action routes answer 204, or 200 with a confirmation object the screens
    /// do not read — either way the body is discarded and only the status
    /// matters.
    private func requestVoid(
        _ method: AgentHTTPMethod,
        _ path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        contentType: String? = nil,
        scopes: [AgentScope] = [.read],
        timeout: TimeInterval = AgentClient.defaultTimeout
    ) async throws {
        _ = try await send(
            method,
            path,
            query: query,
            body: body,
            contentType: contentType,
            scopes: scopes,
            timeout: timeout
        )
    }

    /// The raw bytes of a response — file downloads, where there is no JSON to
    /// decode and the content may not be text at all.
    public func rawData(
        _ path: String,
        query: [URLQueryItem] = [],
        timeout: TimeInterval = AgentClient.fileTimeout
    ) async throws -> Data {
        try await send(.get, path, query: query, scopes: [.read], timeout: timeout)
    }

    /// Transport, authentication and the single retry.
    private func send(
        _ method: AgentHTTPMethod,
        _ path: String,
        query: [URLQueryItem],
        body: Data? = nil,
        contentType: String? = nil,
        scopes: [AgentScope],
        timeout: TimeInterval
    ) async throws -> Data {
        do {
            return try await attempt(
                method, path, query: query, body: body,
                contentType: contentType, scopes: scopes, timeout: timeout
            )
        } catch let error as ServerOSError where error.needsFreshCredential {
            // Retry exactly once, and only for `auth_expired`.
            //
            // One retry covers the real cause: a token minted moments ago that
            // aged out while the request queued behind a slow tunnel. A second
            // failure means something durable is wrong — this Mac's clock is
            // genuinely off, or the agent's is — and looping would not fix it.
            // It would also feed the agent's per-peer failure tracker, which
            // locks a noisy client out for a minute after ten failures, turning
            // a recoverable hiccup into a minute of downtime.
            return try await attempt(
                method, path, query: query, body: body,
                contentType: contentType, scopes: scopes, timeout: timeout
            )
        }
    }

    /// One attempt: a fresh token, one round trip, one translated failure.
    private func attempt(
        _ method: AgentHTTPMethod,
        _ path: String,
        query: [URLQueryItem],
        body: Data?,
        contentType: String?,
        scopes: [AgentScope],
        timeout: TimeInterval
    ) async throws -> Data {
        let url = try makeURL(path: path, query: query)

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = method.rawValue
        urlRequest.timeoutInterval = timeout
        // Minted here, inside the attempt, so a retry never reuses a token the
        // agent has already seen.
        urlRequest.setValue("Bearer \(minter.mint(scopes: scopes))", forHTTPHeaderField: "Authorization")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        // A tunnelled agent's answers are live state; a cached metric is a lie.
        urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
        if let body {
            urlRequest.httpBody = body
            urlRequest.setValue(contentType ?? "application/json", forHTTPHeaderField: "Content-Type")
        }

        let received: (Data, URLResponse)
        do {
            received = try await session.data(for: urlRequest)
        } catch {
            // Covers cancellation too: `URLSession` turns a cancelled Task into
            // `URLError.cancelled`, which maps to the `cancelled` code.
            throw ServerOSError.transport(error, serverName: serverName)
        }

        guard let http = received.1 as? HTTPURLResponse else {
            throw ServerOSError(
                code: "unexpected_response",
                headline: "ServerOS didn't understand the server's reply.",
                causes: ["Something other than the agent may be answering on this port."],
                technical: "\(path): the reply was not an HTTP response",
                isRetryable: false
            )
        }

        guard (200..<300).contains(http.statusCode) else {
            throw failure(from: received.0, status: http.statusCode, endpoint: path)
        }
        return received.0
    }

    /// Turn a non-2xx body into something a person can read.
    private func failure(from data: Data, status: Int, endpoint: String) -> ServerOSError {
        if let wire = try? decoder.decode(WireError.self, from: data) {
            return ServerOSError.from(wire: wire, status: status)
        }
        // No envelope at all: a truncated reply, or something that is not the
        // agent listening on this port.
        let preview = String(data: data.prefix(512), encoding: .utf8) ?? ""
        return ServerOSError(
            code: "http_\(status)",
            headline: "The server\(serverName.isEmpty ? "" : " \(serverName)") refused that request.",
            causes: [
                "The agent may be a different version to this app",
                "Something other than the ServerOS agent may be answering on this port",
            ],
            technical: "\(endpoint) → HTTP \(status)\n\(preview)",
            isRetryable: status >= 500
        )
    }

    // MARK: - URL construction

    /// Build the request URL, percent-encoding every query value.
    ///
    /// The query is assembled by hand rather than left to `URLComponents`,
    /// which leaves `+` alone — and a `+` in a log filter or a file path would
    /// reach the agent as a space.
    private func makeURL(path: String, query: [URLQueryItem]) throws -> URL {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw AgentClient.badURL(path: path)
        }
        components.percentEncodedPath = path
        if query.isEmpty {
            components.percentEncodedQuery = nil
        } else {
            let pairs = query.map { item in
                "\(AgentClient.escape(item.name))=\(AgentClient.escape(item.value ?? ""))"
            }
            components.percentEncodedQuery = pairs.joined(separator: "&")
        }
        guard let url = components.url else {
            throw AgentClient.badURL(path: path)
        }
        return url
    }

    private static func badURL(path: String) -> ServerOSError {
        ServerOSError(
            code: "invalid_request",
            headline: "ServerOS couldn't build that request.",
            causes: [],
            technical: "could not compose a URL for \(path)",
            isRetryable: false
        )
    }

    /// Percent-encode to RFC 3986 unreserved characters only.
    ///
    /// Deliberately stricter than `addingPercentEncoding(withAllowedCharacters:
    /// .urlQueryAllowed)`, which permits `+`, `&`, `=` and `/` through — all of
    /// which change the meaning of a query or a path when they appear inside a
    /// *value* such as `/var/log/nginx/access.log` or a unit name.
    static func escape(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.utf8.count)
        for byte in Array(text.utf8) {
            if AgentClient.isUnreserved(byte) {
                out.append(Character(UnicodeScalar(byte)))
            } else {
                out.append("%")
                out.append(AgentClient.hexDigit(byte >> 4))
                out.append(AgentClient.hexDigit(byte))
            }
        }
        return out
    }

    /// `A-Z a-z 0-9 - . _ ~` — everything else is encoded.
    private static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x41...0x5A, 0x61...0x7A, 0x30...0x39:
            return true
        case 0x2D, 0x2E, 0x5F, 0x7E:
            return true
        default:
            return false
        }
    }

    private static func hexDigit(_ value: UInt8) -> Character {
        let digits: [Character] = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "A", "B", "C", "D", "E", "F",
        ]
        return digits[Int(value & 0x0F)]
    }

    /// The parameters `/v1/logs/file` and `/v1/logs/journal` share.
    private static func logQuery(
        extra: [URLQueryItem],
        lines: Int,
        since: Int64?,
        filter: String?,
        isRegex: Bool
    ) -> [URLQueryItem] {
        var query = extra
        query.append(URLQueryItem(name: "lines", value: String(lines)))
        if let since {
            query.append(URLQueryItem(name: "since", value: String(since)))
        }
        if let filter, !filter.isEmpty {
            query.append(URLQueryItem(name: "filter", value: filter))
            query.append(URLQueryItem(name: "regex", value: isRegex ? "true" : "false"))
        }
        return query
    }

    private func encodeBody<Body: Encodable>(_ value: Body, endpoint: String) throws -> Data {
        do {
            return try encoder.encode(value)
        } catch {
            throw ServerOSError(
                code: "invalid_request",
                headline: "ServerOS couldn't prepare that request.",
                causes: [],
                technical: "\(endpoint): \(error)",
                isRetryable: false
            )
        }
    }
}

// MARK: - Small private shapes

/// The verbs the agent's router registers. Spelled out rather than using raw
/// strings at call sites, so a typo is a compile error.
private enum AgentHTTPMethod: String, Sendable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case patch = "PATCH"
    case delete = "DELETE"
}

private struct SignalBody: Encodable {
    let signal: String
}

private struct SSHKeyBody: Encodable {
    let key: String
}

private struct PathBody: Encodable {
    let path: String
}

private struct RenameBody: Encodable {
    let from: String
    let to: String
}

private struct ChmodBody: Encodable {
    let path: String
    /// Octal as text. `0640` is a JSON syntax error and `640` decimal is not
    /// what anyone means, so the agent takes a string.
    let mode: String
}
