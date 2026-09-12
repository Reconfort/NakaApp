//! Marshalling and unmarshalling of D-Bus values.
//!
//! Both directions are **driven by a signature**, never by inspecting the
//! value. See the alignment table in the [`super`] module docs; every `align`
//! call below is there because of it, and the offsets are relative to the start
//! of the buffer, which for a body is the same thing as relative to the start
//! of the message (the header is padded to 8, the maximum alignment).

use super::DBusError;
use super::signature::{SigType, parse_signature};
use super::value::DValue;

/// Maximum bytes in a single array, per the specification (2^26).
pub const MAX_ARRAY_LEN: usize = 67_108_864;

/// Byte order of a message. We always *write* little-endian, but a conforming
/// peer may write either, so the reader is parameterised.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    /// The byte that appears first in a message header.
    pub fn code(self) -> u8 {
        match self {
            Endian::Little => b'l',
            Endian::Big => b'B',
        }
    }

    pub fn from_code(c: u8) -> Result<Endian, DBusError> {
        match c {
            b'l' => Ok(Endian::Little),
            b'B' => Ok(Endian::Big),
            other => Err(DBusError::protocol(format!(
                "invalid endianness byte 0x{other:02x} (expected 'l' or 'B')"
            ))),
        }
    }
}

// ---------------------------------------------------------------- writing --

/// Appends marshalled values to a byte buffer.
pub struct Writer {
    buf: Vec<u8>,
    endian: Endian,
}

impl Writer {
    pub fn new(endian: Endian) -> Self {
        Writer { buf: Vec::with_capacity(256), endian }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Pad with zero bytes until the write position is a multiple of `a`.
    pub fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        match self.endian {
            Endian::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }

    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        match self.endian {
            Endian::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }

    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        match self.endian {
            Endian::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }

    /// Overwrite a previously written u32 in place — used to backfill array and
    /// body lengths that are only known after their contents are written.
    fn patch_u32(&mut self, at: usize, v: u32) {
        let bytes = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.buf[at..at + 4].copy_from_slice(&bytes);
    }

    /// `s` / `o`: 4-aligned u32 length, the UTF-8 bytes, then a NUL.
    pub fn write_string(&mut self, s: &str) -> Result<(), DBusError> {
        if s.as_bytes().contains(&0) {
            return Err(DBusError::protocol("string contains an embedded NUL"));
        }
        let len = u32::try_from(s.len())
            .map_err(|_| DBusError::protocol("string longer than u32::MAX"))?;
        self.write_u32(len);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// `g`: a *one-byte* length, the bytes, then a NUL. Unaligned — the length
    /// being a `u8` is precisely why a signature has alignment 1.
    pub fn write_signature(&mut self, s: &str) -> Result<(), DBusError> {
        let len = u8::try_from(s.len())
            .map_err(|_| DBusError::protocol("signature longer than 255 bytes"))?;
        self.buf.push(len);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// Marshal a sequence of values against a sequence of types.
    pub fn write_values(&mut self, types: &[SigType], values: &[DValue]) -> Result<(), DBusError> {
        if types.len() != values.len() {
            return Err(DBusError::protocol(format!(
                "signature declares {} value(s) but {} were supplied",
                types.len(),
                values.len()
            )));
        }
        for (t, v) in types.iter().zip(values) {
            self.write_value(t, v)?;
        }
        Ok(())
    }

    /// Marshal one value as `ty`.
    pub fn write_value(&mut self, ty: &SigType, v: &DValue) -> Result<(), DBusError> {
        match (ty, v) {
            (SigType::Byte, DValue::Byte(b)) => self.write_u8(*b),
            (SigType::Boolean, DValue::Bool(b)) => self.write_u32(u32::from(*b)),
            (SigType::Int16, DValue::Int16(n)) => self.write_u16(*n as u16),
            (SigType::Uint16, DValue::Uint16(n)) => self.write_u16(*n),
            (SigType::Int32, DValue::Int32(n)) => self.write_u32(*n as u32),
            (SigType::Uint32, DValue::Uint32(n)) => self.write_u32(*n),
            (SigType::Int64, DValue::Int64(n)) => self.write_u64(*n as u64),
            (SigType::Uint64, DValue::Uint64(n)) => self.write_u64(*n),
            (SigType::Double, DValue::Double(n)) => self.write_u64(n.to_bits()),
            (SigType::Str, DValue::Str(s)) => self.write_string(s)?,
            (SigType::ObjectPath, DValue::ObjectPath(s)) => {
                validate_object_path(s)?;
                self.write_string(s)?;
            }
            (SigType::Sig, DValue::Signature(s)) => {
                parse_signature(s)?;
                self.write_signature(s)?;
            }
            (SigType::Variant, DValue::Variant(inner)) => {
                let inner_ty = inner.signature()?;
                self.write_signature(&inner_ty.code())?;
                self.write_value(&inner_ty, inner)?;
            }
            (SigType::Array(elem), DValue::Array(items)) => {
                self.write_array(elem, items)?;
            }
            (SigType::Struct(fields), DValue::Struct(values)) => {
                if fields.len() != values.len() {
                    return Err(DBusError::protocol(format!(
                        "struct `{}` has {} field(s) but {} were supplied",
                        ty.code(),
                        fields.len(),
                        values.len()
                    )));
                }
                self.align(8);
                for (f, val) in fields.iter().zip(values) {
                    self.write_value(f, val)?;
                }
            }
            (SigType::DictEntry(kt, vt), DValue::DictEntry(k, val)) => {
                self.align(8);
                self.write_value(kt, k)?;
                self.write_value(vt, val)?;
            }
            (expected, got) => {
                return Err(DBusError::protocol(format!(
                    "cannot marshal {got:?} as `{}`",
                    expected.code()
                )));
            }
        }
        Ok(())
    }

    fn write_array(&mut self, elem: &SigType, items: &[DValue]) -> Result<(), DBusError> {
        // u32 byte-length, then padding to the *element's* alignment, then the
        // elements. The padding is NOT counted in the length, and is written
        // even for an empty array.
        self.align(4);
        let len_at = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 4]);
        self.align(elem.alignment());
        let start = self.buf.len();
        for item in items {
            self.write_value(elem, item)?;
        }
        let len = self.buf.len() - start;
        if len > MAX_ARRAY_LEN {
            return Err(DBusError::TooLarge { size: len, max: MAX_ARRAY_LEN });
        }
        self.patch_u32(len_at, len as u32);
        Ok(())
    }
}

// ---------------------------------------------------------------- reading --

/// Reads marshalled values out of a byte slice.
///
/// Position is absolute within `buf`, because alignment is computed from the
/// start of the message. Header fields are read from the whole message buffer;
/// the body is read from a slice that begins on an 8-byte boundary, which is
/// congruent for every alignment in the format.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], endian: Endian) -> Self {
        Reader { buf, pos: 0, endian }
    }

    /// Start reading at `pos` — used to skip the 12-byte fixed header.
    pub fn at(buf: &'a [u8], endian: Endian, pos: usize) -> Self {
        Reader { buf, pos, endian }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn need(&self, n: usize) -> Result<(), DBusError> {
        if self.remaining() < n {
            return Err(DBusError::protocol(format!(
                "message truncated: needed {n} byte(s) at offset {}, {} remain",
                self.pos,
                self.remaining()
            )));
        }
        Ok(())
    }

    /// Skip padding, verifying it is zero. A conforming sender always writes
    /// zeroes; non-zero padding is a sign of a corrupt or hostile stream, and
    /// the reference implementation rejects it too.
    pub fn align(&mut self, a: usize) -> Result<(), DBusError> {
        let target = self.pos.div_ceil(a) * a;
        if target > self.buf.len() {
            return Err(DBusError::protocol(format!(
                "message truncated inside {a}-byte alignment padding at offset {}",
                self.pos
            )));
        }
        for i in self.pos..target {
            if self.buf[i] != 0 {
                return Err(DBusError::protocol(format!(
                    "non-zero alignment padding (0x{:02x}) at offset {i}",
                    self.buf[i]
                )));
            }
        }
        self.pos = target;
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8, DBusError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16, DBusError> {
        self.align(2)?;
        self.need(2)?;
        let b: [u8; 2] = self.buf[self.pos..self.pos + 2].try_into().unwrap_or([0; 2]);
        self.pos += 2;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    pub fn read_u32(&mut self) -> Result<u32, DBusError> {
        self.align(4)?;
        self.need(4)?;
        let b: [u8; 4] = self.buf[self.pos..self.pos + 4].try_into().unwrap_or([0; 4]);
        self.pos += 4;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    pub fn read_u64(&mut self) -> Result<u64, DBusError> {
        self.align(8)?;
        self.need(8)?;
        let b: [u8; 8] = self.buf[self.pos..self.pos + 8].try_into().unwrap_or([0; 8]);
        self.pos += 8;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }

    pub fn read_string(&mut self) -> Result<String, DBusError> {
        let len = self.read_u32()? as usize;
        self.need(len + 1)?;
        let bytes = &self.buf[self.pos..self.pos + len];
        if bytes.contains(&0) {
            return Err(DBusError::protocol("string contains an embedded NUL"));
        }
        if self.buf[self.pos + len] != 0 {
            return Err(DBusError::protocol("string is not NUL-terminated"));
        }
        let s = std::str::from_utf8(bytes)
            .map_err(|e| DBusError::protocol(format!("string is not valid UTF-8: {e}")))?
            .to_owned();
        self.pos += len + 1;
        Ok(s)
    }

    pub fn read_signature(&mut self) -> Result<String, DBusError> {
        let len = self.read_u8()? as usize;
        self.need(len + 1)?;
        let bytes = &self.buf[self.pos..self.pos + len];
        if self.buf[self.pos + len] != 0 {
            return Err(DBusError::protocol("signature is not NUL-terminated"));
        }
        let s = std::str::from_utf8(bytes)
            .map_err(|_| DBusError::protocol("signature is not valid UTF-8"))?
            .to_owned();
        self.pos += len + 1;
        Ok(s)
    }

    /// Read a sequence of values described by `types`.
    pub fn read_values(&mut self, types: &[SigType]) -> Result<Vec<DValue>, DBusError> {
        let mut out = Vec::with_capacity(types.len());
        for t in types {
            out.push(self.read_value(t)?);
        }
        Ok(out)
    }

    /// Read one value of type `ty`.
    pub fn read_value(&mut self, ty: &SigType) -> Result<DValue, DBusError> {
        Ok(match ty {
            SigType::Byte => DValue::Byte(self.read_u8()?),
            SigType::Boolean => match self.read_u32()? {
                0 => DValue::Bool(false),
                1 => DValue::Bool(true),
                other => {
                    return Err(DBusError::protocol(format!(
                        "boolean must be 0 or 1, got {other}"
                    )));
                }
            },
            SigType::Int16 => DValue::Int16(self.read_u16()? as i16),
            SigType::Uint16 => DValue::Uint16(self.read_u16()?),
            SigType::Int32 => DValue::Int32(self.read_u32()? as i32),
            SigType::Uint32 => DValue::Uint32(self.read_u32()?),
            SigType::Int64 => DValue::Int64(self.read_u64()? as i64),
            SigType::Uint64 => DValue::Uint64(self.read_u64()?),
            SigType::Double => DValue::Double(f64::from_bits(self.read_u64()?)),
            SigType::Str => DValue::Str(self.read_string()?),
            SigType::ObjectPath => {
                let s = self.read_string()?;
                validate_object_path(&s)?;
                DValue::ObjectPath(s)
            }
            SigType::Sig => {
                let s = self.read_signature()?;
                parse_signature(&s)?;
                DValue::Signature(s)
            }
            SigType::Variant => {
                let sig = self.read_signature()?;
                let types = parse_signature(&sig)?;
                if types.len() != 1 {
                    return Err(DBusError::protocol(format!(
                        "variant must hold exactly one value, signature was `{sig}`"
                    )));
                }
                DValue::Variant(Box::new(self.read_value(&types[0])?))
            }
            SigType::Array(elem) => {
                let len = self.read_u32()? as usize;
                if len > MAX_ARRAY_LEN {
                    return Err(DBusError::TooLarge { size: len, max: MAX_ARRAY_LEN });
                }
                self.align(elem.alignment())?;
                let start = self.pos;
                self.need(len)?;
                let end = start + len;
                let mut items = Vec::new();
                while self.pos < end {
                    items.push(self.read_value(elem)?);
                    if self.pos > end {
                        return Err(DBusError::protocol(format!(
                            "array element of type `{}` overran the declared length of {len}",
                            elem.code()
                        )));
                    }
                }
                DValue::Array(items)
            }
            SigType::Struct(fields) => {
                self.align(8)?;
                let mut vals = Vec::with_capacity(fields.len());
                for f in fields {
                    vals.push(self.read_value(f)?);
                }
                DValue::Struct(vals)
            }
            SigType::DictEntry(kt, vt) => {
                self.align(8)?;
                let k = self.read_value(kt)?;
                let v = self.read_value(vt)?;
                DValue::DictEntry(Box::new(k), Box::new(v))
            }
        })
    }
}

/// Validate an object path: `/`, or `/`-separated non-empty elements of
/// `[A-Za-z0-9_]`.
///
/// Worth enforcing on both sides. Outbound, it stops a caller turning a unit
/// name into a malformed path that the bus would reject by *dropping the
/// connection*; inbound, it keeps a bad path from reaching the rest of the
/// agent as if it were trustworthy.
pub fn validate_object_path(p: &str) -> Result<(), DBusError> {
    if p.is_empty() {
        return Err(DBusError::protocol("object path is empty"));
    }
    if !p.starts_with('/') {
        return Err(DBusError::protocol(format!(
            "object path `{p}` does not start with `/`"
        )));
    }
    if p == "/" {
        return Ok(());
    }
    if p.ends_with('/') {
        return Err(DBusError::protocol(format!("object path `{p}` has a trailing `/`")));
    }
    for element in p[1..].split('/') {
        if element.is_empty() {
            return Err(DBusError::protocol(format!(
                "object path `{p}` has an empty element"
            )));
        }
        if !element.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(DBusError::protocol(format!(
                "object path `{p}` has an element with invalid characters"
            )));
        }
    }
    Ok(())
}
