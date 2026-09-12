//! The PostgreSQL v3 frontend/backend wire protocol, encoder and decoder.
//!
//! # Why implement this at all
//!
//! The workspace takes no third-party crates (see the root `Cargo.toml`), so
//! `postgres`/`tokio-postgres` are not available to us. That constraint turns
//! out to be cheap here: the agent needs a *tiny* slice of the protocol — start
//! up, authenticate, run a fixed set of read-only statements in the Simple
//! Query protocol, read text-format rows, shut down. That is roughly a dozen
//! message types out of forty-odd, and none of the hard parts (extended query,
//! binary formats, COPY, replication, pipelining) are on the path.
//!
//! Owning the codec also buys something a general-purpose driver cannot give
//! us: the agent decides exactly which statements exist, so the read-only guard
//! in [`crate::client`] is enforceable rather than advisory.
//!
//! # Shape of the protocol
//!
//! Every message after the handshake is `[u8 type][i32 length][payload]`, where
//! the length *includes its own four bytes* but not the type byte. The
//! StartupMessage is the one exception: it has no type byte, because at that
//! point the server does not yet know which protocol version it is speaking.
//!
//! # Framing safety
//!
//! The declared length is attacker-controlled the moment something other than
//! PostgreSQL answers on the port, so it is bounds-checked against
//! [`MAX_MESSAGE_LEN`] before a single byte is allocated. [`MessageReader`] is
//! generic over `Read` and buffers internally, so a message split across
//! arbitrarily many `read` calls reassembles correctly — TCP gives no record
//! boundaries and a 4 KiB `RowDescription` routinely arrives in pieces.

use std::io::{Read, Write};

use crate::error::{PgError, ServerError};

/// Protocol version 3.0, as the `i32` the StartupMessage carries: major 3 in
/// the high 16 bits, minor 0 in the low 16 (`3 << 16 == 196608`).
pub const PROTOCOL_VERSION_3: i32 = 196_608;

/// Largest backend message we will allocate for.
///
/// Nothing the agent asks for comes close: the biggest realistic response is a
/// `pg_stat_activity` row set in the low kilobytes. The cap exists so that a
/// hostile or confused peer cannot make us allocate on its say-so.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// How much we ask the kernel for per `read`.
const READ_CHUNK: usize = 8192;

// ---------------------------------------------------------------------------
// Frontend messages (we send these)
// ---------------------------------------------------------------------------

/// Encode a StartupMessage: `[i32 len][i32 196608][key\0value\0]...\0`.
///
/// No type byte — see the module docs.
pub fn encode_startup(params: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());
    for (k, v) in params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0); // terminator for the parameter list

    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Frame a typed frontend message around an already-built payload.
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(kind);
    out.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `p` PasswordMessage: a NUL-terminated password (cleartext or `md5...`).
pub fn encode_password(password: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(password.len() + 1);
    payload.extend_from_slice(password);
    payload.push(0);
    frame(b'p', &payload)
}

/// `p` SASLInitialResponse: mechanism name, then an `i32`-prefixed response
/// (`-1` when there is none — we always have one).
pub fn encode_sasl_initial(mechanism: &str, initial_response: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(mechanism.len() + initial_response.len() + 5);
    payload.extend_from_slice(mechanism.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&(initial_response.len() as i32).to_be_bytes());
    payload.extend_from_slice(initial_response);
    frame(b'p', &payload)
}

/// `p` SASLResponse: the raw mechanism data, with no NUL and no length prefix
/// (the message length already delimits it).
pub fn encode_sasl_response(data: &[u8]) -> Vec<u8> {
    frame(b'p', data)
}

/// `Q` Query — the Simple Query protocol.
pub fn encode_query(sql: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(sql.len() + 1);
    payload.extend_from_slice(sql.as_bytes());
    payload.push(0);
    frame(b'Q', &payload)
}

/// `X` Terminate — a clean goodbye, so the server logs a normal disconnect
/// rather than "unexpected EOF on client connection".
pub fn encode_terminate() -> Vec<u8> {
    frame(b'X', &[])
}

// ---------------------------------------------------------------------------
// Backend messages (we receive these)
// ---------------------------------------------------------------------------

/// The `R` message's sub-types, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// 0 — authentication succeeded.
    Ok,
    /// 3 — send the password in the clear.
    CleartextPassword,
    /// 5 — send `md5(...)`, salted with these four bytes.
    Md5Password([u8; 4]),
    /// 10 — SASL, with the mechanisms the server is willing to accept.
    Sasl(Vec<String>),
    /// 11 — SASL continue, carrying the server-first message.
    SaslContinue(Vec<u8>),
    /// 12 — SASL final, carrying the server signature.
    SaslFinal(Vec<u8>),
}

/// One column's metadata from a `T` RowDescription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    /// Column name as the server labelled it.
    pub name: String,
    /// OID of the table this column came from, or 0 if it is computed.
    pub table_oid: i32,
    /// Attribute number within that table, or 0.
    pub column_id: i16,
    /// OID of the column's data type.
    pub type_oid: i32,
    /// Type size in bytes; negative for variable-length types.
    pub type_size: i16,
    /// Type modifier (e.g. the `n` in `varchar(n)`).
    pub type_modifier: i32,
    /// 0 = text, 1 = binary. Always 0 for us — see [`crate::client`].
    pub format: i16,
}

/// A decoded backend message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// `R`
    Authentication(Auth),
    /// `S` — a runtime parameter the server wants us to know about.
    ParameterStatus { name: String, value: String },
    /// `K` — the keys needed to cancel a query on this connection.
    BackendKeyData { pid: i32, secret: i32 },
    /// `Z` — the server is idle again. The byte is the transaction status:
    /// `I` idle, `T` in a transaction, `E` in a failed transaction.
    ReadyForQuery(u8),
    /// `T`
    RowDescription(Vec<FieldDescription>),
    /// `D` — one row; `None` is a SQL `NULL` (wire length `-1`), which is
    /// distinct from a zero-length string.
    DataRow(Vec<Option<Vec<u8>>>),
    /// `C` — e.g. `SELECT 12`.
    CommandComplete(String),
    /// `E`
    Error(ServerError),
    /// `N` — informational; never fatal.
    Notice(ServerError),
    /// `I` — the statement was empty.
    EmptyQueryResponse,
    /// `A` — a `LISTEN`/`NOTIFY` delivery. Decoded so the frame is consumed
    /// correctly, then ignored: the agent never issues `LISTEN`.
    Notification { pid: i32, channel: String, payload: String },
    /// A well-formed message of a type we do not use (`n` NoData, `s`
    /// PortalSuspended, ...). Kept as a variant rather than an error so a
    /// future server release cannot break the connection.
    Unhandled(u8),
}

/// Reads length-prefixed backend messages out of any `Read`.
///
/// Owns the transport so that `PgConnection` has a single object to borrow; the
/// `Read + Write` impl block adds [`MessageReader::send`] for the frontend
/// direction.
pub struct MessageReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: Read> MessageReader<R> {
    /// Wrap a transport.
    pub fn new(inner: R) -> Self {
        MessageReader { inner, buf: Vec::with_capacity(READ_CHUNK), pos: 0 }
    }

    /// Borrow the underlying transport (to set socket timeouts, mostly).
    pub fn transport(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Read exactly one backend message, blocking until it is complete.
    pub fn read_message(&mut self) -> Result<Backend, PgError> {
        // Drop consumed bytes so the buffer does not grow without bound across
        // a long-lived connection.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }

        self.fill_to(5)?;
        let kind = self.buf[0];
        let declared = i32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);

        // `declared` counts itself, so anything under 4 is nonsense, and we
        // check the ceiling before using it as a capacity.
        if declared < 4 {
            return Err(PgError::Protocol(format!(
                "message type {:?} declared an impossible length of {declared}",
                kind as char
            )));
        }
        let len = declared as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(PgError::Protocol(format!(
                "message type {:?} declared a length of {len} bytes, over the {MAX_MESSAGE_LEN} \
                 byte limit; this is not a PostgreSQL server",
                kind as char
            )));
        }

        let total = len + 1; // + the type byte
        self.fill_to(total)?;
        let message = decode(kind, &self.buf[5..total])?;
        self.pos = total;
        Ok(message)
    }

    /// Block until the buffer holds at least `n` bytes.
    fn fill_to(&mut self, n: usize) -> Result<(), PgError> {
        let mut chunk = [0u8; READ_CHUNK];
        while self.buf.len() < n {
            let got = self.inner.read(&mut chunk)?;
            if got == 0 {
                return Err(PgError::Protocol(format!(
                    "server closed the connection after {} of {n} expected bytes",
                    self.buf.len()
                )));
            }
            self.buf.extend_from_slice(&chunk[..got]);
        }
        Ok(())
    }
}

impl<R: Read + Write> MessageReader<R> {
    /// Write one frontend message and flush it.
    pub fn send(&mut self, message: &[u8]) -> Result<(), PgError> {
        self.inner.write_all(message)?;
        self.inner.flush()?;
        Ok(())
    }
}

/// Decode a message payload (everything after the type byte and length).
fn decode(kind: u8, payload: &[u8]) -> Result<Backend, PgError> {
    let mut c = Cursor::new(payload, kind);
    match kind {
        b'R' => Ok(Backend::Authentication(decode_auth(&mut c)?)),
        b'S' => Ok(Backend::ParameterStatus { name: c.cstr()?, value: c.cstr()? }),
        b'K' => Ok(Backend::BackendKeyData { pid: c.i32()?, secret: c.i32()? }),
        b'Z' => Ok(Backend::ReadyForQuery(c.u8()?)),
        b'T' => {
            let count = c.i16()?;
            if count < 0 {
                return Err(c.bad("negative field count in RowDescription"));
            }
            let mut fields = Vec::with_capacity(count as usize);
            for _ in 0..count {
                fields.push(FieldDescription {
                    name: c.cstr()?,
                    table_oid: c.i32()?,
                    column_id: c.i16()?,
                    type_oid: c.i32()?,
                    type_size: c.i16()?,
                    type_modifier: c.i32()?,
                    format: c.i16()?,
                });
            }
            Ok(Backend::RowDescription(fields))
        }
        b'D' => {
            let count = c.i16()?;
            if count < 0 {
                return Err(c.bad("negative column count in DataRow"));
            }
            let mut values = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let len = c.i32()?;
                if len == -1 {
                    values.push(None); // SQL NULL, not an empty string
                } else if len < 0 {
                    return Err(c.bad("negative column length other than -1 in DataRow"));
                } else {
                    values.push(Some(c.bytes(len as usize)?.to_vec()));
                }
            }
            Ok(Backend::DataRow(values))
        }
        b'C' => Ok(Backend::CommandComplete(c.cstr()?)),
        b'E' => Ok(Backend::Error(decode_fields(&mut c)?)),
        b'N' => Ok(Backend::Notice(decode_fields(&mut c)?)),
        b'I' => Ok(Backend::EmptyQueryResponse),
        b'A' => Ok(Backend::Notification {
            pid: c.i32()?,
            channel: c.cstr()?,
            payload: c.cstr()?,
        }),
        other => Ok(Backend::Unhandled(other)),
    }
}

fn decode_auth(c: &mut Cursor<'_>) -> Result<Auth, PgError> {
    match c.i32()? {
        0 => Ok(Auth::Ok),
        3 => Ok(Auth::CleartextPassword),
        5 => {
            let salt = c.bytes(4)?;
            Ok(Auth::Md5Password([salt[0], salt[1], salt[2], salt[3]]))
        }
        10 => {
            // A list of NUL-terminated mechanism names, ended by an empty one.
            let mut mechanisms = Vec::new();
            loop {
                let m = c.cstr()?;
                if m.is_empty() {
                    break;
                }
                mechanisms.push(m);
            }
            Ok(Auth::Sasl(mechanisms))
        }
        11 => Ok(Auth::SaslContinue(c.rest().to_vec())),
        12 => Ok(Auth::SaslFinal(c.rest().to_vec())),
        // 2 Kerberos V5, 7 GSSAPI, 8 GSSContinue, 9 SSPI, 13 SASL over GSS.
        // None of these are reachable for a local socket in any supported
        // configuration, and guessing at them would be worse than saying so.
        other => Err(PgError::UnsupportedAuth(other)),
    }
}

/// Decode the NUL-terminated `[code][value]` pairs of an `E`/`N` message,
/// which end with a lone zero byte.
fn decode_fields(c: &mut Cursor<'_>) -> Result<ServerError, PgError> {
    let mut e = ServerError::default();
    loop {
        let code = c.u8()?;
        if code == 0 {
            break;
        }
        let value = c.cstr()?;
        match code {
            b'S' => e.severity = value,
            // `V` is the never-localised severity (9.6+). Prefer it when we see
            // it, so a server running under a German locale still says FATAL.
            b'V' => e.severity = value,
            b'C' => e.code = value,
            b'M' => e.message = value,
            b'D' => e.detail = Some(value),
            b'H' => e.hint = Some(value),
            _ => {} // position, file, line, routine, schema, ...: not shown
        }
    }
    Ok(e)
}

/// A bounds-checked reader over one message payload.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
    kind: u8,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], kind: u8) -> Self {
        Cursor { data, at: 0, kind }
    }

    fn bad(&self, what: &str) -> PgError {
        PgError::Protocol(format!("{what} (message type {:?})", self.kind as char))
    }

    fn need(&self, n: usize) -> Result<(), PgError> {
        if self.data.len() - self.at < n {
            return Err(self.bad(&format!(
                "truncated: wanted {n} more bytes at offset {} of {}",
                self.at,
                self.data.len()
            )));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, PgError> {
        self.need(1)?;
        let b = self.data[self.at];
        self.at += 1;
        Ok(b)
    }

    fn i16(&mut self) -> Result<i16, PgError> {
        self.need(2)?;
        let v = i16::from_be_bytes([self.data[self.at], self.data[self.at + 1]]);
        self.at += 2;
        Ok(v)
    }

    fn i32(&mut self) -> Result<i32, PgError> {
        self.need(4)?;
        let v = i32::from_be_bytes([
            self.data[self.at],
            self.data[self.at + 1],
            self.data[self.at + 2],
            self.data[self.at + 3],
        ]);
        self.at += 4;
        Ok(v)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], PgError> {
        self.need(n)?;
        let s = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn cstr(&mut self) -> Result<String, PgError> {
        let end = self.data[self.at..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| self.bad("unterminated string"))?;
        let s = &self.data[self.at..self.at + end];
        self.at += end + 1;
        // `client_encoding=UTF8` is set in the StartupMessage, so the server
        // has promised UTF-8. Lossy conversion would silently corrupt a
        // database name; refusing is the honest response.
        String::from_utf8(s.to_vec())
            .map_err(|_| self.bad("string was not valid UTF-8 despite client_encoding=UTF8"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.at..];
        self.at = self.data.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Read` that hands over at most `chunk` bytes per call, to prove the
    /// reader reassembles messages split across arbitrary read boundaries.
    struct Dribble {
        data: Vec<u8>,
        at: usize,
        chunk: usize,
    }

    impl Read for Dribble {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.chunk.min(out.len()).min(self.data.len() - self.at);
            out[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    fn reader(data: Vec<u8>) -> MessageReader<Dribble> {
        MessageReader::new(Dribble { data, at: 0, chunk: usize::MAX })
    }

    // ---- frontend encoding, byte for byte ---------------------------------

    #[test]
    fn startup_message_bytes_are_exact() {
        let bytes = encode_startup(&[("user", "alice"), ("database", "app")]);
        let expected: Vec<u8> = [
            // length: 4 (itself) + 4 (version) + "user\0alice\0" (11)
            //         + "database\0app\0" (13) + 1 (terminator) = 33
            &[0, 0, 0, 33][..],
            &[0, 3, 0, 0][..],         // 196608
            b"user\0alice\0",
            b"database\0app\0",
            &[0][..],
        ]
        .concat();
        assert_eq!(bytes, expected);
        // The declared length must equal the real length, including itself.
        assert_eq!(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize, bytes.len());
    }

    #[test]
    fn startup_message_has_no_type_byte() {
        let bytes = encode_startup(&[("user", "u")]);
        // First byte is the high byte of the length, which for any realistic
        // startup message is zero — not an ASCII message type.
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[4..8], &PROTOCOL_VERSION_3.to_be_bytes());
    }

    #[test]
    fn protocol_version_is_three_dot_zero() {
        assert_eq!(PROTOCOL_VERSION_3, 3 << 16);
    }

    #[test]
    fn password_message_bytes_are_exact() {
        assert_eq!(encode_password(b"hunter2"), b"p\0\0\0\x0chunter2\0".to_vec());
    }

    #[test]
    fn query_message_bytes_are_exact() {
        assert_eq!(encode_query("SELECT 1"), b"Q\0\0\0\x0dSELECT 1\0".to_vec());
    }

    #[test]
    fn terminate_message_bytes_are_exact() {
        assert_eq!(encode_terminate(), vec![b'X', 0, 0, 0, 4]);
    }

    #[test]
    fn sasl_initial_response_frames_mechanism_then_length_prefixed_body() {
        let m = encode_sasl_initial("SCRAM-SHA-256", b"n,,n=*,r=abc");
        assert_eq!(m[0], b'p');
        let len = i32::from_be_bytes([m[1], m[2], m[3], m[4]]) as usize;
        assert_eq!(len + 1, m.len());
        assert_eq!(&m[5..18], b"SCRAM-SHA-256");
        assert_eq!(m[18], 0);
        assert_eq!(i32::from_be_bytes([m[19], m[20], m[21], m[22]]), 12);
        assert_eq!(&m[23..], b"n,,n=*,r=abc");
    }

    #[test]
    fn sasl_response_is_raw_with_no_terminator() {
        let m = encode_sasl_response(b"c=biws,r=abc,p=xyz");
        assert_eq!(m[0], b'p');
        assert_eq!(&m[5..], b"c=biws,r=abc,p=xyz");
        assert_eq!(*m.last().unwrap(), b'z'); // no trailing NUL
    }

    // ---- backend decoding --------------------------------------------------

    /// Build a typed backend message, for fixtures.
    fn msg(kind: u8, payload: &[u8]) -> Vec<u8> {
        frame(kind, payload)
    }

    #[test]
    fn decodes_authentication_ok() {
        let m = msg(b'R', &0i32.to_be_bytes());
        assert_eq!(reader(m).read_message().unwrap(), Backend::Authentication(Auth::Ok));
    }

    #[test]
    fn decodes_cleartext_password_request() {
        let m = msg(b'R', &3i32.to_be_bytes());
        assert_eq!(
            reader(m).read_message().unwrap(),
            Backend::Authentication(Auth::CleartextPassword)
        );
    }

    #[test]
    fn decodes_md5_password_request_with_salt() {
        let m = msg(b'R', &[&5i32.to_be_bytes()[..], &[0xde, 0xad, 0xbe, 0xef]].concat());
        assert_eq!(
            reader(m).read_message().unwrap(),
            Backend::Authentication(Auth::Md5Password([0xde, 0xad, 0xbe, 0xef]))
        );
    }

    #[test]
    fn decodes_sasl_mechanism_list() {
        let m = msg(
            b'R',
            &[&10i32.to_be_bytes()[..], b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"].concat(),
        );
        let want = vec!["SCRAM-SHA-256-PLUS".to_string(), "SCRAM-SHA-256".to_string()];
        assert_eq!(reader(m).read_message().unwrap(), Backend::Authentication(Auth::Sasl(want)));
    }

    #[test]
    fn decodes_sasl_continue_and_final_payloads() {
        let c = msg(b'R', &[&11i32.to_be_bytes()[..], b"r=abc,s=c2FsdA==,i=4096"].concat());
        assert_eq!(
            reader(c).read_message().unwrap(),
            Backend::Authentication(Auth::SaslContinue(b"r=abc,s=c2FsdA==,i=4096".to_vec()))
        );
        let f = msg(b'R', &[&12i32.to_be_bytes()[..], b"v=sig"].concat());
        assert_eq!(
            reader(f).read_message().unwrap(),
            Backend::Authentication(Auth::SaslFinal(b"v=sig".to_vec()))
        );
    }

    #[test]
    fn rejects_gssapi_and_sspi_by_code() {
        for code in [2i32, 7, 9] {
            let m = msg(b'R', &code.to_be_bytes());
            match reader(m).read_message() {
                Err(PgError::UnsupportedAuth(n)) => assert_eq!(n, code),
                other => panic!("expected UnsupportedAuth({code}), got {other:?}"),
            }
        }
    }

    #[test]
    fn decodes_parameter_status_and_backend_key_data() {
        let p = msg(b'S', b"server_version\x0016.13\x00");
        assert_eq!(
            reader(p).read_message().unwrap(),
            Backend::ParameterStatus { name: "server_version".into(), value: "16.13".into() }
        );
        let k = msg(b'K', &[&1234i32.to_be_bytes()[..], &5678i32.to_be_bytes()[..]].concat());
        assert_eq!(
            reader(k).read_message().unwrap(),
            Backend::BackendKeyData { pid: 1234, secret: 5678 }
        );
    }

    #[test]
    fn decodes_ready_for_query_transaction_status() {
        let m = msg(b'Z', b"I");
        assert_eq!(reader(m).read_message().unwrap(), Backend::ReadyForQuery(b'I'));
    }

    #[test]
    fn decodes_row_description_fixture() {
        // One column: name "id", table 16384, attr 1, type oid 23 (int4),
        // size 4, modifier -1, format 0 (text).
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(b"id\0");
        payload.extend_from_slice(&16384i32.to_be_bytes());
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&23i32.to_be_bytes());
        payload.extend_from_slice(&4i16.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        payload.extend_from_slice(&0i16.to_be_bytes());

        let got = reader(msg(b'T', &payload)).read_message().unwrap();
        assert_eq!(
            got,
            Backend::RowDescription(vec![FieldDescription {
                name: "id".into(),
                table_oid: 16384,
                column_id: 1,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: 0,
            }])
        );
    }

    #[test]
    fn data_row_distinguishes_null_from_empty_string() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3i16.to_be_bytes());
        payload.extend_from_slice(&2i32.to_be_bytes());
        payload.extend_from_slice(b"hi");
        payload.extend_from_slice(&(-1i32).to_be_bytes()); // SQL NULL
        payload.extend_from_slice(&0i32.to_be_bytes()); // empty, not NULL

        let got = reader(msg(b'D', &payload)).read_message().unwrap();
        assert_eq!(
            got,
            Backend::DataRow(vec![Some(b"hi".to_vec()), None, Some(Vec::new())])
        );
    }

    #[test]
    fn rejects_negative_column_length_other_than_null() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&(-7i32).to_be_bytes());
        assert!(matches!(
            reader(msg(b'D', &payload)).read_message(),
            Err(PgError::Protocol(_))
        ));
    }

    #[test]
    fn decodes_command_complete_and_empty_query() {
        assert_eq!(
            reader(msg(b'C', b"SELECT 12\0")).read_message().unwrap(),
            Backend::CommandComplete("SELECT 12".into())
        );
        assert_eq!(
            reader(msg(b'I', b"")).read_message().unwrap(),
            Backend::EmptyQueryResponse
        );
    }

    #[test]
    fn decodes_error_response_fixture() {
        let payload =
            b"SFATAL\0C28P01\0Mpassword authentication failed for user \"bob\"\0Dsome detail\0Htry again\0Fauth.c\0L328\0\0";
        let got = reader(msg(b'E', payload)).read_message().unwrap();
        match got {
            Backend::Error(e) => {
                assert_eq!(e.severity, "FATAL");
                assert_eq!(e.code, "28P01");
                assert_eq!(e.message, "password authentication failed for user \"bob\"");
                assert_eq!(e.detail.as_deref(), Some("some detail"));
                assert_eq!(e.hint.as_deref(), Some("try again"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn error_response_prefers_the_unlocalised_severity_field() {
        // `S` may be translated; `V` never is. A German server sends both.
        let payload = b"SFATAL-Meldung\0VFATAL\0C3D000\0Mnope\0\0";
        match reader(msg(b'E', payload)).read_message().unwrap() {
            Backend::Error(e) => assert_eq!(e.severity, "FATAL"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn decodes_notice_response_separately_from_error() {
        let got = reader(msg(b'N', b"SNOTICE\0C00000\0Mrelation exists\0\0")).read_message().unwrap();
        assert!(matches!(got, Backend::Notice(_)));
    }

    #[test]
    fn error_response_missing_terminator_is_rejected() {
        assert!(matches!(
            reader(msg(b'E', b"SFATAL\0C28P01\0")).read_message(),
            Err(PgError::Protocol(_))
        ));
    }

    #[test]
    fn decodes_notification_response() {
        let payload = [&42i32.to_be_bytes()[..], b"chan\0body\0"].concat();
        assert_eq!(
            reader(msg(b'A', &payload)).read_message().unwrap(),
            Backend::Notification { pid: 42, channel: "chan".into(), payload: "body".into() }
        );
    }

    #[test]
    fn unknown_message_types_are_skipped_not_fatal() {
        // `n` NoData belongs to the extended query protocol; we must consume
        // the frame and carry on rather than kill the connection.
        let stream = [msg(b'n', b""), msg(b'Z', b"I")].concat();
        let mut r = reader(stream);
        assert_eq!(r.read_message().unwrap(), Backend::Unhandled(b'n'));
        assert_eq!(r.read_message().unwrap(), Backend::ReadyForQuery(b'I'));
    }

    // ---- framing safety ----------------------------------------------------

    #[test]
    fn reassembles_a_message_split_across_single_byte_reads() {
        let stream = [
            msg(b'S', b"server_version\x0016.13\x00"),
            msg(b'Z', b"I"),
        ]
        .concat();
        let mut r = MessageReader::new(Dribble { data: stream, at: 0, chunk: 1 });
        assert_eq!(
            r.read_message().unwrap(),
            Backend::ParameterStatus { name: "server_version".into(), value: "16.13".into() }
        );
        assert_eq!(r.read_message().unwrap(), Backend::ReadyForQuery(b'I'));
    }

    #[test]
    fn reads_several_messages_out_of_one_read() {
        let stream = [msg(b'Z', b"I"), msg(b'Z', b"T"), msg(b'Z', b"E")].concat();
        let mut r = reader(stream);
        assert_eq!(r.read_message().unwrap(), Backend::ReadyForQuery(b'I'));
        assert_eq!(r.read_message().unwrap(), Backend::ReadyForQuery(b'T'));
        assert_eq!(r.read_message().unwrap(), Backend::ReadyForQuery(b'E'));
    }

    #[test]
    fn rejects_an_absurd_declared_length_without_allocating() {
        // 1 GiB, well over MAX_MESSAGE_LEN. Only 5 bytes are ever supplied, so
        // if the reader tried to wait for the body this would hang instead.
        let mut m = vec![b'D'];
        m.extend_from_slice(&(1024i32 * 1024 * 1024).to_be_bytes());
        match reader(m).read_message() {
            Err(PgError::Protocol(msg)) => assert!(msg.contains("limit"), "{msg}"),
            other => panic!("expected a length rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_declared_length_below_the_header() {
        let mut m = vec![b'D'];
        m.extend_from_slice(&3i32.to_be_bytes());
        assert!(matches!(reader(m).read_message(), Err(PgError::Protocol(_))));
    }

    #[test]
    fn truncated_stream_reports_a_clean_protocol_error() {
        // A `K` message promising 8 payload bytes but delivering 2.
        let mut m = vec![b'K'];
        m.extend_from_slice(&12i32.to_be_bytes());
        m.extend_from_slice(&[0, 0]);
        match reader(m).read_message() {
            Err(PgError::Protocol(msg)) => assert!(msg.contains("closed"), "{msg}"),
            other => panic!("expected a truncation error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_payload_inside_a_complete_frame_is_rejected() {
        // Frame claims 4 columns but the payload stops after one.
        let mut payload = Vec::new();
        payload.extend_from_slice(&4i16.to_be_bytes());
        payload.extend_from_slice(&1i32.to_be_bytes());
        payload.push(b'x');
        assert!(matches!(
            reader(msg(b'D', &payload)).read_message(),
            Err(PgError::Protocol(_))
        ));
    }

    #[test]
    fn non_utf8_string_is_rejected_rather_than_mangled() {
        let m = msg(b'S', b"name\0\xff\xfe\0");
        match reader(m).read_message() {
            Err(PgError::Protocol(msg)) => assert!(msg.contains("UTF-8"), "{msg}"),
            other => panic!("expected a UTF-8 rejection, got {other:?}"),
        }
    }
}
