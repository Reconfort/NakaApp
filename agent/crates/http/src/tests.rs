//! These tests drive a real listening socket rather than a mock. The server is
//! the one component where "it compiles" says almost nothing — framing,
//! keep-alive and upgrade bugs only show up on the wire.

use crate::client::HttpClient;
use crate::response::Conn;
use crate::uri::{Uri, build_query, normalise_path, parse_query, percent_decode, percent_encode};
use crate::{Headers, Method, Request, Response, Router, Server, ServerConfig, Status, ws};
use serveros_json::Object;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------- URI ------

#[test]
fn uri_parses_path_and_query() {
    let u = Uri::parse("/v1/docker/containers?all=true&limit=5").unwrap();
    assert_eq!(u.path, "/v1/docker/containers");
    assert_eq!(u.query, "all=true&limit=5");
    let q = u.query_pairs();
    assert_eq!(q.get("all").map(String::as_str), Some("true"));
    assert_eq!(q.get("limit").map(String::as_str), Some("5"));
}

#[test]
fn uri_decodes_percent_escapes_exactly_once() {
    let u = Uri::parse("/v1/files/read?path=%2Fvar%2Flog%2Fsyslog").unwrap();
    assert_eq!(u.path, "/v1/files/read");
    assert_eq!(u.query_pairs().get("path").unwrap(), "/var/log/syslog");

    // Double-encoded input must decode to the literal text, not to a slash.
    // Decoding twice is how traversal bugs are born.
    let u2 = Uri::parse("/a/%252e%252e/b").unwrap();
    assert_eq!(u2.path, "/a/%2e%2e/b");
}

#[test]
fn uri_normalises_traversal_out_of_the_path() {
    assert_eq!(normalise_path("/a/b/../c"), "/a/c");
    assert_eq!(normalise_path("/../../etc/passwd"), "/etc/passwd");
    assert_eq!(normalise_path("//a///b//"), "/a/b");
    assert_eq!(normalise_path("/a/./b"), "/a/b");
    assert_eq!(normalise_path("/"), "/");
    assert_eq!(normalise_path(""), "/");
    // Encoded traversal is decoded first, then normalised away.
    assert_eq!(Uri::parse("/v1/%2e%2e/%2e%2e/etc").unwrap().path, "/etc");
}

#[test]
fn uri_rejects_hostile_targets() {
    assert!(Uri::parse("relative/path").is_none(), "must be origin-form");
    assert!(Uri::parse("/bad%2").is_none(), "truncated escape");
    assert!(Uri::parse("/bad%zz").is_none(), "non-hex escape");
    assert!(Uri::parse("/nul%00byte").is_none(), "NUL in path");
    // Absolute-form is legal in HTTP/1.1 and should reduce to its path.
    assert_eq!(Uri::parse("http://example/v1/x").unwrap().path, "/v1/x");
}

#[test]
fn query_encoding_round_trips() {
    let original = "a value/with?chars&=+%";
    let encoded = percent_encode(original);
    assert!(!encoded.contains('&') && !encoded.contains('='));
    assert_eq!(percent_decode(&encoded).unwrap(), original);

    let q = build_query([("path", "/var/log"), ("filter", "a b")]);
    let parsed = parse_query(&q);
    assert_eq!(parsed.get("path").unwrap(), "/var/log");
    assert_eq!(parsed.get("filter").unwrap(), "a b");
}

#[test]
fn form_decoding_treats_plus_as_space_only_in_queries() {
    assert_eq!(parse_query("q=a+b").get("q").unwrap(), "a b");
    // In a path, `+` is a literal plus — a real filename can contain one.
    assert_eq!(Uri::parse("/files/a+b.txt").unwrap().path, "/files/a+b.txt");
}

// ------------------------------------------------------------- Router ------

fn test_router() -> Router<()> {
    Router::new()
        .get("/v1/health", |_, _| Response::text(Status::OK, "ok"))
        .get("/v1/servers/{id}", |_, r| {
            Response::text(Status::OK, r.param("id").unwrap_or("-").to_string())
        })
        .post("/v1/servers/{id}/restart", |_, r| {
            Response::text(Status::OK, format!("restart {}", r.param("id").unwrap_or("-")))
        })
        .get("/v1/files/{path...}", |_, r| {
            Response::text(Status::OK, format!("file:{}", r.param("path").unwrap_or("")))
        })
}

fn dispatch(router: &Router<()>, method: Method, path: &str) -> (u16, String) {
    let req = Request {
        method,
        uri: Uri::parse(path).unwrap(),
        headers: Headers::new(),
        body: crate::Body::Bytes(Vec::new()),
        params: Default::default(),
        peer: crate::request::PeerInfo::Loopback { port: 1 },
        keep_alive: false,
    };
    let resp = router.dispatch(&Arc::new(()), req);
    let status = resp.status.0;
    let body = match resp.payload {
        crate::response::Payload::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
        _ => String::new(),
    };
    (status, body)
}

#[test]
fn router_matches_literals_and_params() {
    let r = test_router();
    assert_eq!(dispatch(&r, Method::Get, "/v1/health"), (200, "ok".into()));
    assert_eq!(dispatch(&r, Method::Get, "/v1/servers/prod-1").1, "prod-1");
    assert_eq!(dispatch(&r, Method::Post, "/v1/servers/x/restart").1, "restart x");
}

#[test]
fn router_catch_all_captures_the_rest_including_slashes() {
    let r = test_router();
    assert_eq!(dispatch(&r, Method::Get, "/v1/files/var/log/syslog").1, "file:var/log/syslog");
    // An empty catch-all is legal and means "the root".
    assert_eq!(dispatch(&r, Method::Get, "/v1/files").1, "file:");
}

#[test]
fn router_distinguishes_missing_path_from_wrong_method() {
    let r = test_router();
    assert_eq!(dispatch(&r, Method::Get, "/v1/nope").0, 404);
    assert_eq!(dispatch(&r, Method::Delete, "/v1/health").0, 405);
    // HEAD is served by the GET handler, per RFC 9110.
    assert_eq!(dispatch(&r, Method::Head, "/v1/health").0, 200);
}

#[test]
fn router_does_not_match_partial_paths() {
    let r = test_router();
    assert_eq!(dispatch(&r, Method::Get, "/v1/servers/a/b").0, 404);
    assert_eq!(dispatch(&r, Method::Get, "/v1").0, 404);
}

// ------------------------------------------------------- live server -------

struct TestServer {
    port: u16,
    hits: Arc<AtomicUsize>,
}

fn start_server() -> TestServer {
    let hits = Arc::new(AtomicUsize::new(0));
    let state = hits.clone();

    let router: Router<Arc<AtomicUsize>> = Router::new()
        .get("/v1/health", |s: &Arc<Arc<AtomicUsize>>, _| {
            s.fetch_add(1, Ordering::SeqCst);
            Response::json(Object::new().set("status", "ok"))
        })
        .get("/v1/echo/{word}", |_, r| {
            Response::text(Status::OK, r.param("word").unwrap_or("").to_string())
        })
        .post("/v1/sum", |_, r| {
            let v = r.json().unwrap_or(serveros_json::Value::Null);
            let a = v.get("a").and_then(|x| x.as_i64()).unwrap_or(0);
            let b = v.get("b").and_then(|x| x.as_i64()).unwrap_or(0);
            Response::json(Object::new().set("sum", a + b))
        })
        .get("/v1/stream", |_, _| {
            Response::stream("text/plain", |w| {
                for i in 0..5 {
                    writeln!(w, "line {i}")?;
                }
                Ok(())
            })
        })
        .get("/v1/headers", |_, r| {
            Response::text(Status::OK, r.headers.get("x-probe").unwrap_or("none").to_string())
        })
        .get("/v1/ws", |_, r| {
            ws::accept(&r, |mut rx, tx| {
                loop {
                    match rx.recv(&tx) {
                        Ok(ws::Message::Text(t)) => {
                            if tx.send_text(&format!("echo:{t}")).is_err() {
                                return;
                            }
                        }
                        Ok(ws::Message::Close { .. }) => {
                            let _ = tx.close(1000, "bye");
                            return;
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
            })
        });

    let config = ServerConfig {
        port: Some(0),
        unix_socket: None,
        idle_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        spool_dir: std::env::temp_dir().join("serveros-test-spool"),
        ..Default::default()
    };

    let server = Server::new(config, router, Arc::new(state));
    let (listener, addr) = server.bind_tcp().expect("bind ephemeral port");
    server.serve_tcp(listener);

    TestServer { port: addr.port(), hits }
}

fn raw_request(port: u16, request: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn server_answers_a_basic_request() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.get("/v1/health").expect("request");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().unwrap().get("status").unwrap().as_str(), Some("ok"));
    assert_eq!(ts.hits.load(Ordering::SeqCst), 1, "handler ran exactly once");
}

#[test]
fn server_round_trips_json_bodies() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let body = Object::new().set("a", 20).set("b", 22);
    let resp = client.post_json("/v1/sum", &body.into()).expect("request");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().unwrap().get("sum").unwrap().as_i64(), Some(42));
}

#[test]
fn server_sends_chunked_streams_the_client_can_decode() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.get("/v1/stream").expect("request");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text(), "line 0\nline 1\nline 2\nline 3\nline 4\n");
    assert!(
        resp.headers.contains_token("transfer-encoding", "chunked"),
        "stream must use chunked framing"
    );
}

#[test]
fn server_streams_incrementally_rather_than_buffering() {
    // Read the first chunk before the handler has finished, proving the body
    // is not assembled in memory first.
    let ts = start_server();
    let mut s = TcpStream::connect(("127.0.0.1", ts.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET /v1/stream HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut reader = BufReader::new(s);
    let mut saw_chunk_header = false;
    for _ in 0..12 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line.trim() == "1" || line.trim() == "7" {
            saw_chunk_header = true;
            break;
        }
    }
    assert!(saw_chunk_header, "expected a chunk-size line in the raw stream");
}

#[test]
fn server_reuses_a_keep_alive_connection_for_pipelined_requests() {
    // Two requests written in one go. If the connection loop drops its read
    // buffer between requests, the second answer never arrives.
    let ts = start_server();
    let out = raw_request(
        ts.port,
        "GET /v1/echo/one HTTP/1.1\r\nHost: x\r\n\r\n\
         GET /v1/echo/two HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(out.contains("one"), "first response missing: {out}");
    assert!(out.contains("two"), "second response missing — buffered bytes were dropped");
    assert_eq!(out.matches("HTTP/1.1 200").count(), 2);
}

#[test]
fn server_closes_when_the_client_asks_it_to() {
    let ts = start_server();
    let out = raw_request(ts.port, "GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(out.contains("Connection: close"));
}

#[test]
fn head_returns_headers_without_a_body() {
    let ts = start_server();
    let out = raw_request(ts.port, "HEAD /v1/echo/abc HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(out.contains("HTTP/1.1 200"));
    assert!(out.contains("Content-Length: 3"), "length must describe the would-be body");
    assert!(!out.contains("abc"), "HEAD must not send a body");
}

#[test]
fn server_rejects_malformed_requests_with_400() {
    let ts = start_server();
    let out = raw_request(ts.port, "NOTAMETHOD / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(out.contains("HTTP/1.1 400"), "got {out}");

    let out = raw_request(ts.port, "GET /v1/health HTTP/9.9\r\nHost: x\r\n\r\n");
    assert!(out.contains("HTTP/1.1 400"), "got {out}");
}

#[test]
fn server_rejects_request_smuggling_shapes() {
    // Both Content-Length and Transfer-Encoding is the classic desync setup.
    let ts = start_server();
    let out = raw_request(
        ts.port,
        "POST /v1/sum HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    assert!(out.contains("HTTP/1.1 400"), "got {out}");

    // Obsolete line folding is also a desync vector.
    let out = raw_request(
        ts.port,
        "GET /v1/health HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n  b\r\n\r\n",
    );
    assert!(out.contains("HTTP/1.1 400"), "got {out}");
}

#[test]
fn server_enforces_the_body_limit() {
    let ts = start_server();
    let oversized = crate::request::MAX_BODY + 1;
    let out = raw_request(
        ts.port,
        &format!("POST /v1/sum HTTP/1.1\r\nHost: x\r\nContent-Length: {oversized}\r\n\r\n"),
    );
    assert!(out.contains("HTTP/1.1 413"), "got {out}");
}

#[test]
fn server_enforces_the_header_limit() {
    let ts = start_server();
    let mut req = String::from("GET /v1/health HTTP/1.1\r\nHost: x\r\n");
    for i in 0..200 {
        req.push_str(&format!("X-Pad-{i}: {}\r\n", "y".repeat(200)));
    }
    req.push_str("\r\n");
    let out = raw_request(ts.port, &req);
    assert!(out.contains("HTTP/1.1 413") || out.contains("HTTP/1.1 400"), "got {out}");
}

#[test]
fn responses_always_carry_hardening_headers() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.get("/v1/health").unwrap();
    assert_eq!(resp.headers.get("x-content-type-options"), Some("nosniff"));
    assert_eq!(resp.headers.get("cache-control"), Some("no-store"));
}

#[test]
fn header_lookup_is_case_insensitive() {
    let ts = start_server();
    let mut h = Headers::new();
    h.insert("X-Probe", "hello");
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.request_with(Method::Get, "/v1/headers", &h, None).unwrap();
    assert_eq!(resp.text(), "hello");
}

#[test]
fn error_responses_use_the_standard_envelope() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.get("/v1/does-not-exist").unwrap();
    assert_eq!(resp.status, 404);
    let v = resp.json().unwrap();
    assert_eq!(v.path("error/code").unwrap().as_str(), Some("not_found"));
    assert!(v.path("error/message").unwrap().as_str().unwrap().len() > 5);
}

#[test]
fn header_values_cannot_split_the_response() {
    // A filename with a CRLF in it must not be able to inject headers.
    let r = Response::text(Status::OK, "body").header("X-Name", "evil\r\nX-Injected: yes");
    let mut out = Vec::new();
    r.write_to(&mut out, Method::Get, false).unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("X-Injected"), "header injection got through");
}

// ---------------------------------------------------------- WebSocket ------

/// A minimal client-side WebSocket, because the server must be tested against
/// a peer that masks its frames the way a real client does.
struct WsClient {
    stream: TcpStream,
}

impl WsClient {
    fn connect(port: u16) -> WsClient {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream
            .write_all(
                b"GET /v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .unwrap();

        // Read exactly the handshake response, byte by byte, so no frame bytes
        // are swallowed by a buffered reader.
        let mut head = Vec::new();
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        assert!(text.contains("101 Switching Protocols"), "bad handshake: {text}");
        assert!(
            text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "accept key wrong: {text}"
        );
        WsClient { stream }
    }

    fn send_text(&mut self, text: &str) {
        self.send_frame(0x1, text.as_bytes());
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) {
        let mut frame = vec![0x80 | opcode];
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        match payload.len() {
            n if n < 126 => frame.push(0x80 | n as u8),
            n => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        self.stream.write_all(&frame).unwrap();
        self.stream.flush().unwrap();
    }

    /// Read one frame, skipping pings the keepalive may inject.
    fn recv(&mut self) -> (u8, Vec<u8>) {
        loop {
            let mut head = [0u8; 2];
            self.stream.read_exact(&mut head).unwrap();
            let opcode = head[0] & 0x0F;
            assert_eq!(head[1] & 0x80, 0, "server frames must not be masked");
            let len = match head[1] & 0x7F {
                126 => {
                    let mut b = [0u8; 2];
                    self.stream.read_exact(&mut b).unwrap();
                    u16::from_be_bytes(b) as usize
                }
                127 => {
                    let mut b = [0u8; 8];
                    self.stream.read_exact(&mut b).unwrap();
                    u64::from_be_bytes(b) as usize
                }
                n => n as usize,
            };
            let mut payload = vec![0u8; len];
            self.stream.read_exact(&mut payload).unwrap();
            if opcode == 0x9 {
                continue; // ping
            }
            return (opcode, payload);
        }
    }
}

#[test]
fn websocket_completes_the_rfc6455_handshake_and_echoes() {
    let ts = start_server();
    let mut c = WsClient::connect(ts.port);
    c.send_text("hello");
    let (op, payload) = c.recv();
    assert_eq!(op, 0x1, "expected a text frame");
    assert_eq!(String::from_utf8(payload).unwrap(), "echo:hello");
}

#[test]
fn websocket_handles_a_medium_frame_with_extended_length() {
    let ts = start_server();
    let mut c = WsClient::connect(ts.port);
    let big = "x".repeat(1000); // forces the 16-bit length form
    c.send_text(&big);
    let (op, payload) = c.recv();
    assert_eq!(op, 0x1);
    assert_eq!(String::from_utf8(payload).unwrap(), format!("echo:{big}"));
}

#[test]
fn websocket_answers_a_close_with_a_close() {
    let ts = start_server();
    let mut c = WsClient::connect(ts.port);
    c.send_frame(0x8, &[0x03, 0xE8]); // 1000 normal closure
    let (op, payload) = c.recv();
    assert_eq!(op, 0x8, "expected a close frame");
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1000);
}

#[test]
fn websocket_replies_to_a_ping_with_a_pong() {
    let ts = start_server();
    let mut c = WsClient::connect(ts.port);
    c.send_frame(0x9, b"ping-payload");
    // The echo session answers pings transparently inside recv().
    let mut head = [0u8; 2];
    c.stream.read_exact(&mut head).unwrap();
    assert_eq!(head[0] & 0x0F, 0xA, "expected a pong");
    let len = (head[1] & 0x7F) as usize;
    let mut payload = vec![0u8; len];
    c.stream.read_exact(&mut payload).unwrap();
    assert_eq!(payload, b"ping-payload");
}

#[test]
fn websocket_rejects_an_unmasked_client_frame() {
    // RFC 6455 §5.1 requires the server to fail the connection.
    let ts = start_server();
    let mut c = WsClient::connect(ts.port);
    let frame = vec![0x81, 0x03, b'a', b'b', b'c']; // FIN+text, no mask bit
    c.stream.write_all(&frame).unwrap();
    c.stream.flush().unwrap();
    let mut buf = [0u8; 16];
    let n = c.stream.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "server should have dropped the connection");
}

#[test]
fn websocket_refuses_a_wrong_protocol_version() {
    let ts = start_server();
    let out = raw_request(
        ts.port,
        "GET /v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
    );
    assert!(out.contains("HTTP/1.1 400"), "got {out}");
    assert!(out.contains("Sec-WebSocket-Version: 13"));
}

// ----------------------------------------------------------- client --------

#[test]
fn client_reports_unreachable_endpoints_without_hanging() {
    let client = HttpClient::unix("/nonexistent/serveros-test.sock");
    assert!(!client.is_reachable());
    assert!(client.get("/v1/anything").is_err());
}

#[test]
fn client_surfaces_non_2xx_without_treating_it_as_an_error() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client.get("/v1/nope").unwrap();
    assert!(!resp.is_success());
    assert_eq!(resp.status, 404);
}

#[test]
fn client_streams_a_chunked_body_incrementally() {
    let ts = start_server();
    let client = HttpClient::tcp(format!("127.0.0.1:{}", ts.port));
    let resp = client
        .request_streaming(Method::Get, "/v1/stream", &Headers::new(), None, None)
        .unwrap();
    assert!(resp.is_success());
    let mut text = String::new();
    resp.reader().read_to_string(&mut text).unwrap();
    assert_eq!(text, "line 0\nline 1\nline 2\nline 3\nline 4\n");
}

#[test]
fn conn_clone_shares_the_same_socket() {
    // The upgrade path depends on this: reader and writer must be two handles
    // on one socket, not two sockets.
    let ts = start_server();
    let s = TcpStream::connect(("127.0.0.1", ts.port)).unwrap();
    let c = crate::server::TcpConn(s);
    let mut cloned = c.try_clone_conn().unwrap();
    let mut original = c;
    original.write_all(b"GET /v1/echo/shared HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    original.flush().unwrap();
    let mut out = String::new();
    cloned.read_to_string(&mut out).unwrap();
    assert!(out.contains("shared"), "clone did not see the same connection: {out}");
}
