//! D-Bus messages: the fixed header, the header-field array, and the body.
//!
//! Layout of every message on the wire:
//!
//! ```text
//!  offset  0 ..  1   endianness  'l' | 'B'
//!          1 ..  2   message type
//!          2 ..  3   flags
//!          3 ..  4   protocol version (1)
//!          4 ..  8   body length, u32
//!          8 .. 12   serial, u32 (never 0)
//!         12 .. 16   header-field array byte length, u32
//!         16 .. 16+n header fields, a(yv)     <- 16 is already 8-aligned
//!                    padding to the next 8-byte boundary
//!                    body
//! ```
//!
//! The field array's length covers only the field data, so the total message
//! size is `align8(16 + n) + body_length`. Getting that expression wrong is how
//! a client ends up reading the next message's header as this message's body,
//! which is why it lives in exactly one place: [`Message::expected_len`].

use super::DBusError;
use super::marshal::{Endian, Reader, Writer};
use super::signature::{SigType, parse_signature, render_signature};
use super::value::DValue;

/// Hard cap on an accepted message.
///
/// The specification permits 128 MiB. We accept 16 MiB: the largest thing this
/// client ever asks for is `ListUnits` on a very busy host, which is a few
/// hundred kilobytes. A cap that is two orders of magnitude above the real
/// workload still leaves no room for a hostile peer to make the agent — which
/// runs privileged, on someone's production box — allocate itself to death.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// The fixed 12-byte part of the header.
pub const FIXED_HEADER_LEN: usize = 12;

/// Message type, from the `type` byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    MethodCall,
    MethodReturn,
    Error,
    Signal,
}

impl MessageType {
    pub fn code(self) -> u8 {
        match self {
            MessageType::MethodCall => 1,
            MessageType::MethodReturn => 2,
            MessageType::Error => 3,
            MessageType::Signal => 4,
        }
    }

    pub fn from_code(c: u8) -> Result<MessageType, DBusError> {
        match c {
            1 => Ok(MessageType::MethodCall),
            2 => Ok(MessageType::MethodReturn),
            3 => Ok(MessageType::Error),
            4 => Ok(MessageType::Signal),
            other => Err(DBusError::protocol(format!("unknown message type {other}"))),
        }
    }
}

/// `NO_REPLY_EXPECTED`: the peer must not send a method return.
pub const FLAG_NO_REPLY_EXPECTED: u8 = 0x01;
/// `NO_AUTO_START`: do not activate the destination if it is not running.
pub const FLAG_NO_AUTO_START: u8 = 0x02;

// Header field codes.
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SENDER: u8 = 7;
const FIELD_SIGNATURE: u8 = 8;
const FIELD_UNIX_FDS: u8 = 9;

/// A decoded D-Bus message.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub kind: MessageType,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    /// Signature of `body`. `None` means an empty body.
    pub signature: Option<String>,
    pub unix_fds: Option<u32>,
    pub body: Vec<DValue>,
}

impl Message {
    fn blank(kind: MessageType) -> Message {
        Message {
            kind,
            flags: 0,
            serial: 0,
            path: None,
            interface: None,
            member: None,
            error_name: None,
            reply_serial: None,
            destination: None,
            sender: None,
            signature: None,
            unix_fds: None,
            body: Vec::new(),
        }
    }

    /// Build a `METHOD_CALL`. The serial is assigned by the connection.
    pub fn method_call(
        destination: impl Into<String>,
        path: impl Into<String>,
        interface: impl Into<String>,
        member: impl Into<String>,
    ) -> Message {
        let mut m = Message::blank(MessageType::MethodCall);
        m.destination = Some(destination.into());
        m.path = Some(path.into());
        m.interface = Some(interface.into());
        m.member = Some(member.into());
        m
    }

    /// Build a `METHOD_RETURN` in reply to `call`. Used by the test harness's
    /// mock systemd service; the agent itself only ever calls out.
    pub fn method_return(call: &Message) -> Message {
        let mut m = Message::blank(MessageType::MethodReturn);
        m.reply_serial = Some(call.serial);
        m.destination = call.sender.clone();
        m
    }

    /// Build an `ERROR` in reply to `call`.
    pub fn error_reply(
        call: &Message,
        name: impl Into<String>,
        text: impl Into<String>,
    ) -> Message {
        let mut m = Message::blank(MessageType::Error);
        m.reply_serial = Some(call.serial);
        m.destination = call.sender.clone();
        m.error_name = Some(name.into());
        m.signature = Some("s".to_owned());
        m.body = vec![DValue::Str(text.into())];
        m
    }

    /// Attach a body. `signature` is authoritative — it is what lets an empty
    /// array be marshalled at all.
    #[must_use]
    pub fn with_body(mut self, signature: impl Into<String>, body: Vec<DValue>) -> Message {
        let sig = signature.into();
        if sig.is_empty() {
            self.signature = None;
            self.body = Vec::new();
        } else {
            self.signature = Some(sig);
            self.body = body;
        }
        self
    }

    /// The human-readable text of an `ERROR` message, if it carries one.
    pub fn error_text(&self) -> String {
        self.body
            .first()
            .and_then(DValue::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    /// Total length of the message that starts at `head`, which must contain at
    /// least the first 16 bytes. Returns `None` if fewer than 16 bytes are
    /// available.
    pub fn expected_len(head: &[u8]) -> Result<Option<usize>, DBusError> {
        if head.len() < 16 {
            return Ok(None);
        }
        let endian = Endian::from_code(head[0])?;
        if head[3] != 1 {
            return Err(DBusError::protocol(format!(
                "unsupported D-Bus protocol version {} (expected 1)",
                head[3]
            )));
        }
        let read_u32 = |at: usize| -> u32 {
            let b: [u8; 4] = head[at..at + 4].try_into().unwrap_or([0; 4]);
            match endian {
                Endian::Little => u32::from_le_bytes(b),
                Endian::Big => u32::from_be_bytes(b),
            }
        };
        let body_len = read_u32(4) as usize;
        let fields_len = read_u32(12) as usize;
        // align8(16 + fields_len) + body_len, computed without overflowing.
        let after_fields = 16usize
            .checked_add(fields_len)
            .ok_or_else(|| DBusError::protocol("header field array length overflows"))?;
        let body_start = after_fields.div_ceil(8) * 8;
        let total = body_start
            .checked_add(body_len)
            .ok_or_else(|| DBusError::protocol("body length overflows"))?;
        if total > MAX_MESSAGE_SIZE {
            return Err(DBusError::TooLarge { size: total, max: MAX_MESSAGE_SIZE });
        }
        Ok(Some(total))
    }

    /// Serialise. Always little-endian: we are the sender, and every machine
    /// this agent ships on is little-endian, so declaring `l` costs nothing and
    /// saves the peer a byte-swap.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DBusError> {
        self.to_bytes_endian(Endian::Little)
    }

    /// Serialise with an explicit byte order. Only the tests use anything but
    /// little-endian; it exists so the big-endian *reader* path has coverage.
    pub fn to_bytes_endian(&self, endian: Endian) -> Result<Vec<u8>, DBusError> {
        if self.serial == 0 {
            return Err(DBusError::protocol("message serial must not be zero"));
        }

        // Body first: we need its length for the fixed header. Marshalling it
        // into its own buffer is correct because the body always begins on an
        // 8-byte boundary, the maximum alignment in the format.
        let body_bytes = if let Some(sig) = &self.signature {
            let types = parse_signature(sig)?;
            let mut w = Writer::new(endian);
            w.write_values(&types, &self.body)?;
            w.into_bytes()
        } else {
            if !self.body.is_empty() {
                return Err(DBusError::protocol(
                    "message has body values but no signature",
                ));
            }
            Vec::new()
        };

        let mut w = Writer::new(endian);
        w.write_u8(endian.code());
        w.write_u8(self.kind.code());
        w.write_u8(self.flags);
        w.write_u8(1); // protocol version
        w.write_u32(
            u32::try_from(body_bytes.len())
                .map_err(|_| DBusError::protocol("body longer than u32::MAX"))?,
        );
        w.write_u32(self.serial);

        // Header fields, a(yv), written in ascending field-code order so the
        // byte output is deterministic and testable.
        let mut fields: Vec<(u8, DValue)> = Vec::with_capacity(8);
        if let Some(v) = &self.path {
            fields.push((FIELD_PATH, DValue::ObjectPath(v.clone())));
        }
        if let Some(v) = &self.interface {
            fields.push((FIELD_INTERFACE, DValue::Str(v.clone())));
        }
        if let Some(v) = &self.member {
            fields.push((FIELD_MEMBER, DValue::Str(v.clone())));
        }
        if let Some(v) = &self.error_name {
            fields.push((FIELD_ERROR_NAME, DValue::Str(v.clone())));
        }
        if let Some(v) = self.reply_serial {
            fields.push((FIELD_REPLY_SERIAL, DValue::Uint32(v)));
        }
        if let Some(v) = &self.destination {
            fields.push((FIELD_DESTINATION, DValue::Str(v.clone())));
        }
        if let Some(v) = &self.sender {
            fields.push((FIELD_SENDER, DValue::Str(v.clone())));
        }
        if let Some(v) = &self.signature {
            fields.push((FIELD_SIGNATURE, DValue::Signature(v.clone())));
        }
        if let Some(v) = self.unix_fds {
            fields.push((FIELD_UNIX_FDS, DValue::Uint32(v)));
        }

        let entries: Vec<DValue> = fields
            .into_iter()
            .map(|(code, v)| DValue::Struct(vec![DValue::Byte(code), DValue::Variant(Box::new(v))]))
            .collect();
        let fields_ty = SigType::Array(Box::new(SigType::Struct(vec![
            SigType::Byte,
            SigType::Variant,
        ])));
        w.write_value(&fields_ty, &DValue::Array(entries))?;

        // Pad the header out to 8 so the body starts aligned.
        w.align(8);

        let mut out = w.into_bytes();
        out.extend_from_slice(&body_bytes);
        if out.len() > MAX_MESSAGE_SIZE {
            return Err(DBusError::TooLarge { size: out.len(), max: MAX_MESSAGE_SIZE });
        }
        Ok(out)
    }

    /// Parse a complete message. `buf` must be exactly one message.
    pub fn parse(buf: &[u8]) -> Result<Message, DBusError> {
        let total = Message::expected_len(buf)?.ok_or_else(|| {
            DBusError::protocol(format!(
                "message header truncated: {} byte(s), need at least 16",
                buf.len()
            ))
        })?;
        if buf.len() < total {
            return Err(DBusError::protocol(format!(
                "message truncated: header declares {total} bytes, got {}",
                buf.len()
            )));
        }

        let endian = Endian::from_code(buf[0])?;
        let kind = MessageType::from_code(buf[1])?;
        let flags = buf[2];

        let mut r = Reader::at(buf, endian, 4);
        let body_len = r.read_u32()? as usize;
        let serial = r.read_u32()?;
        if serial == 0 {
            return Err(DBusError::protocol("message serial must not be zero"));
        }

        let fields_ty = SigType::Array(Box::new(SigType::Struct(vec![
            SigType::Byte,
            SigType::Variant,
        ])));
        let fields = r.read_value(&fields_ty)?;

        let mut m = Message::blank(kind);
        m.flags = flags;
        m.serial = serial;

        for entry in fields.as_array().unwrap_or(&[]) {
            let Some(pair) = entry.as_struct() else { continue };
            let (Some(DValue::Byte(code)), Some(value)) =
                (pair.first(), pair.get(1).map(DValue::unwrap_variant))
            else {
                continue;
            };
            match *code {
                FIELD_PATH => m.path = value.as_str().map(str::to_owned),
                FIELD_INTERFACE => m.interface = value.as_str().map(str::to_owned),
                FIELD_MEMBER => m.member = value.as_str().map(str::to_owned),
                FIELD_ERROR_NAME => m.error_name = value.as_str().map(str::to_owned),
                FIELD_REPLY_SERIAL => m.reply_serial = value.as_u32(),
                FIELD_DESTINATION => m.destination = value.as_str().map(str::to_owned),
                FIELD_SENDER => m.sender = value.as_str().map(str::to_owned),
                FIELD_SIGNATURE => m.signature = value.as_str().map(str::to_owned),
                FIELD_UNIX_FDS => m.unix_fds = value.as_u32(),
                // Unknown header fields must be ignored, not rejected: that is
                // how the protocol stays extensible.
                _ => {}
            }
        }

        let body_start = r.position().div_ceil(8) * 8;
        if body_start + body_len > buf.len() {
            return Err(DBusError::protocol(
                "declared body extends past the end of the message",
            ));
        }
        if body_len > 0 {
            let sig = m.signature.clone().ok_or_else(|| {
                DBusError::protocol("message has a body but no SIGNATURE header field")
            })?;
            let types = parse_signature(&sig)?;
            let mut br = Reader::new(&buf[body_start..body_start + body_len], endian);
            m.body = br.read_values(&types)?;
            if br.remaining() != 0 {
                return Err(DBusError::protocol(format!(
                    "{} trailing byte(s) after a body of signature `{sig}`",
                    br.remaining()
                )));
            }
        }

        m.validate_required_fields()?;
        Ok(m)
    }

    /// Reject messages that omit a field their type requires. Doing this once,
    /// here, is what lets the rest of the crate `unwrap`-free its way through
    /// `reply_serial` and `error_name`.
    fn validate_required_fields(&self) -> Result<(), DBusError> {
        let missing = |what: &str| {
            Err(DBusError::protocol(format!(
                "{:?} message is missing the {what} header field",
                self.kind
            )))
        };
        match self.kind {
            MessageType::MethodCall => {
                if self.path.is_none() {
                    return missing("PATH");
                }
                if self.member.is_none() {
                    return missing("MEMBER");
                }
            }
            MessageType::MethodReturn => {
                if self.reply_serial.is_none() {
                    return missing("REPLY_SERIAL");
                }
            }
            MessageType::Error => {
                if self.reply_serial.is_none() {
                    return missing("REPLY_SERIAL");
                }
                if self.error_name.is_none() {
                    return missing("ERROR_NAME");
                }
            }
            MessageType::Signal => {
                if self.path.is_none() {
                    return missing("PATH");
                }
                if self.interface.is_none() {
                    return missing("INTERFACE");
                }
                if self.member.is_none() {
                    return missing("MEMBER");
                }
            }
        }
        Ok(())
    }

    /// The signature the body actually has, derived from the values. Used by
    /// tests and by the mock service; prefer the declared `signature` field.
    pub fn derived_signature(&self) -> Result<String, DBusError> {
        let types: Vec<SigType> =
            self.body.iter().map(DValue::signature).collect::<Result<_, _>>()?;
        Ok(render_signature(&types))
    }
}
