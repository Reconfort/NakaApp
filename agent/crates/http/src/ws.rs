//! WebSocket server (RFC 6455).
//!
//! Used for the live channels the desktop app subscribes to: metrics, container
//! and service state, and log tails. Polling those over REST would either be
//! slow or would hammer the server; a single multiplexed socket is both calmer
//! and cheaper.
//!
//! Only the parts a server needs are implemented: no extensions, no
//! compression, no client role.

use crate::response::{Conn, Payload, Response, Status, Upgraded};
use crate::{Headers, Request};
use serveros_crypto::{b64_encode, sha1};
use std::io::{BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Largest single frame accepted from a client. Clients only ever send small
/// control messages (subscribe/unsubscribe), so this is generous.
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl OpCode {
    fn from_u8(v: u8) -> Option<OpCode> {
        Some(match v {
            0x0 => OpCode::Continuation,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            _ => return None,
        })
    }

    fn to_u8(self) -> u8 {
        match self {
            OpCode::Continuation => 0x0,
            OpCode::Text => 0x1,
            OpCode::Binary => 0x2,
            OpCode::Close => 0x8,
            OpCode::Ping => 0x9,
            OpCode::Pong => 0xA,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, OpCode::Close | OpCode::Ping | OpCode::Pong)
    }
}

#[derive(Debug)]
pub enum WsError {
    Io(std::io::Error),
    /// Peer violated the protocol. The session closes with code 1002.
    Protocol(&'static str),
    /// A frame exceeded [`MAX_FRAME`]. Closes with 1009.
    TooLarge,
    /// Normal close.
    Closed,
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Io(e) => write!(f, "io: {e}"),
            WsError::Protocol(m) => write!(f, "protocol error: {m}"),
            WsError::TooLarge => write!(f, "frame too large"),
            WsError::Closed => write!(f, "closed"),
        }
    }
}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        WsError::Io(e)
    }
}

/// A complete application message.
#[derive(Debug, Clone)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close { code: u16, reason: String },
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

/// The write half. Cloneable and internally locked, so a metrics timer thread
/// and a log-tail thread can both push to the same socket.
#[derive(Clone)]
pub struct WsSender {
    inner: Arc<Mutex<Box<dyn Conn>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl WsSender {
    pub fn send_text(&self, text: &str) -> Result<(), WsError> {
        self.send_frame(OpCode::Text, text.as_bytes())
    }

    pub fn send_binary(&self, data: &[u8]) -> Result<(), WsError> {
        self.send_frame(OpCode::Binary, data)
    }

    pub fn ping(&self, payload: &[u8]) -> Result<(), WsError> {
        self.send_frame(OpCode::Ping, payload)
    }

    pub fn pong(&self, payload: &[u8]) -> Result<(), WsError> {
        self.send_frame(OpCode::Pong, payload)
    }

    pub fn close(&self, code: u16, reason: &str) -> Result<(), WsError> {
        if self.closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        self.send_frame_inner(OpCode::Close, &payload)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn send_frame(&self, op: OpCode, payload: &[u8]) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Closed);
        }
        self.send_frame_inner(op, payload)
    }

    fn send_frame_inner(&self, op: OpCode, payload: &[u8]) -> Result<(), WsError> {
        let mut header = Vec::with_capacity(10);
        header.push(0x80 | op.to_u8()); // FIN set; the agent never fragments
        // Server-to-client frames are never masked (RFC 6455 §5.1).
        match payload.len() {
            n if n < 126 => header.push(n as u8),
            n if n <= u16::MAX as usize => {
                header.push(126);
                header.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                header.push(127);
                header.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }

        let mut guard = self.inner.lock().map_err(|_| WsError::Protocol("sender poisoned"))?;
        guard.write_all(&header)?;
        guard.write_all(payload)?;
        guard.flush()?;
        Ok(())
    }
}

/// The read half.
pub struct WsReceiver {
    reader: BufReader<Box<dyn Conn>>,
}

impl WsReceiver {
    /// Read one complete message, transparently reassembling fragments and
    /// answering pings.
    pub fn recv(&mut self, sender: &WsSender) -> Result<Message, WsError> {
        let mut assembled: Vec<u8> = Vec::new();
        let mut message_op: Option<OpCode> = None;

        loop {
            let frame = self.read_frame()?;

            if frame.op.is_control() {
                // Control frames may be interleaved inside a fragmented
                // message and must never themselves be fragmented.
                if !frame.fin {
                    return Err(WsError::Protocol("fragmented control frame"));
                }
                if frame.payload.len() > 125 {
                    return Err(WsError::Protocol("oversized control frame"));
                }
                match frame.op {
                    OpCode::Ping => {
                        sender.pong(&frame.payload)?;
                        continue;
                    }
                    OpCode::Pong => return Ok(Message::Pong(frame.payload)),
                    OpCode::Close => {
                        let (code, reason) = parse_close(&frame.payload);
                        return Ok(Message::Close { code, reason });
                    }
                    _ => unreachable!(),
                }
            }

            match (message_op, frame.op) {
                (None, OpCode::Continuation) => {
                    return Err(WsError::Protocol("continuation without start"));
                }
                (None, op) => message_op = Some(op),
                (Some(_), OpCode::Continuation) => {}
                (Some(_), _) => return Err(WsError::Protocol("nested message start")),
            }

            if assembled.len() + frame.payload.len() > MAX_FRAME {
                return Err(WsError::TooLarge);
            }
            assembled.extend_from_slice(&frame.payload);

            if frame.fin {
                return match message_op {
                    Some(OpCode::Text) => String::from_utf8(assembled)
                        .map(Message::Text)
                        .map_err(|_| WsError::Protocol("text frame is not UTF-8")),
                    _ => Ok(Message::Binary(assembled)),
                };
            }
        }
    }

    fn read_frame(&mut self) -> Result<Frame, WsError> {
        let mut head = [0u8; 2];
        self.reader.read_exact(&mut head)?;

        let fin = head[0] & 0x80 != 0;
        if head[0] & 0x70 != 0 {
            // No extensions were negotiated, so reserved bits must be zero.
            return Err(WsError::Protocol("reserved bits set"));
        }
        let op = OpCode::from_u8(head[0] & 0x0F).ok_or(WsError::Protocol("unknown opcode"))?;

        let masked = head[1] & 0x80 != 0;
        if !masked {
            // RFC 6455 §5.1: a server must close on an unmasked client frame.
            return Err(WsError::Protocol("client frame not masked"));
        }

        let len = match head[1] & 0x7F {
            126 => {
                let mut b = [0u8; 2];
                self.reader.read_exact(&mut b)?;
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                self.reader.read_exact(&mut b)?;
                let n = u64::from_be_bytes(b);
                if n > MAX_FRAME as u64 {
                    return Err(WsError::TooLarge);
                }
                n as usize
            }
            n => n as usize,
        };
        if len > MAX_FRAME {
            return Err(WsError::TooLarge);
        }

        let mut mask = [0u8; 4];
        self.reader.read_exact(&mut mask)?;

        let mut payload = vec![0u8; len];
        self.reader.read_exact(&mut payload)?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }

        Ok(Frame { fin, op, payload })
    }
}

struct Frame {
    fin: bool,
    op: OpCode,
    payload: Vec<u8>,
}

fn parse_close(payload: &[u8]) -> (u16, String) {
    if payload.len() < 2 {
        return (1005, String::new());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
    (code, reason)
}

/// Validate a WebSocket upgrade request and build the 101 response.
///
/// `session` runs on the connection thread once the handshake is written.
pub fn accept(
    req: &Request,
    session: impl FnOnce(WsReceiver, WsSender) + Send + 'static,
) -> Response {
    let Some(key) = req.headers.get("sec-websocket-key") else {
        return Response::error(
            Status::BAD_REQUEST,
            "websocket_handshake_failed",
            "Missing Sec-WebSocket-Key",
        );
    };
    // RFC 6455 fixes the version at 13; anything else must be refused with the
    // versions we do support so the client can retry.
    match req.headers.get("sec-websocket-version") {
        Some("13") => {}
        _ => {
            return Response::error(
                Status::BAD_REQUEST,
                "websocket_version_unsupported",
                "This agent speaks WebSocket version 13",
            )
            .header("Sec-WebSocket-Version", "13");
        }
    }

    let accept_key = b64_encode(&sha1(format!("{}{}", key.trim(), GUID).as_bytes()));

    let mut headers = Headers::new();
    headers.insert("Upgrade", "websocket");
    headers.insert("Connection", "Upgrade");
    headers.insert("Sec-WebSocket-Accept", accept_key);

    Response {
        status: Status::SWITCHING_PROTOCOLS,
        headers,
        payload: Payload::Upgrade(Box::new(move |up: Upgraded| {
            let Upgraded { reader, writer } = up;
            // Liveness is managed by ping/pong from here on, not by the HTTP
            // read timeout — a quiet metrics channel is not a dead one.
            let _ = writer.set_read_timeout(None);
            let sender = WsSender {
                inner: Arc::new(Mutex::new(writer)),
                closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            let receiver = WsReceiver { reader };
            session(receiver, sender);
        })),
    }
}

/// Spawn a thread that pings every `interval` so a silent channel still
/// notices a peer that has gone away.
pub fn spawn_keepalive(sender: WsSender, interval: Duration) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("agent-ws-ping".into())
        .spawn(move || {
            while !sender.is_closed() {
                std::thread::sleep(interval);
                if sender.ping(b"").is_err() {
                    break;
                }
            }
        })
        .expect("spawn websocket keepalive")
}
