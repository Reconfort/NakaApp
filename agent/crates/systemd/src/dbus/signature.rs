//! D-Bus type signatures.
//!
//! A signature is a string of single-character type codes, where containers
//! nest: `a(ssssssouso)` is "array of struct of six strings, object path,
//! uint32, string, object path" — the reply type of systemd's `ListUnits`.
//!
//! We parse signatures into a tree rather than walking the string during
//! marshalling for one reason: **marshalling must be signature-driven**. The
//! value `DValue::Array(vec![])` cannot tell you what it is an array of, and an
//! empty array still has to emit padding to its element's alignment. Only the
//! signature knows.

use super::DBusError;

/// Maximum signature length, per the specification.
pub const MAX_SIGNATURE_LEN: usize = 255;
/// Maximum array nesting, per the specification.
pub const MAX_ARRAY_DEPTH: usize = 32;
/// Maximum struct/dict-entry nesting, per the specification.
pub const MAX_STRUCT_DEPTH: usize = 32;

/// A parsed D-Bus type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigType {
    Byte,
    Boolean,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
    Double,
    Str,
    ObjectPath,
    Sig,
    Variant,
    Array(Box<SigType>),
    Struct(Vec<SigType>),
    DictEntry(Box<SigType>, Box<SigType>),
}

impl SigType {
    /// Byte alignment of a value of this type, counted from the start of the
    /// message. See the module docs of [`super`] for why this is the single
    /// most error-prone part of the format.
    pub fn alignment(&self) -> usize {
        match self {
            SigType::Byte | SigType::Sig | SigType::Variant => 1,
            SigType::Int16 | SigType::Uint16 => 2,
            SigType::Boolean
            | SigType::Int32
            | SigType::Uint32
            | SigType::Str
            | SigType::ObjectPath
            | SigType::Array(_) => 4,
            SigType::Int64
            | SigType::Uint64
            | SigType::Double
            | SigType::Struct(_)
            | SigType::DictEntry(_, _) => 8,
        }
    }

    /// True for the types that may be a dict-entry key.
    pub fn is_basic(&self) -> bool {
        !matches!(
            self,
            SigType::Array(_)
                | SigType::Struct(_)
                | SigType::DictEntry(_, _)
                | SigType::Variant
        )
    }

    /// Render back to the wire form. `render(&parse(s)?) == s` for every valid
    /// signature, which is what the round-trip tests assert.
    pub fn write_code(&self, out: &mut String) {
        match self {
            SigType::Byte => out.push('y'),
            SigType::Boolean => out.push('b'),
            SigType::Int16 => out.push('n'),
            SigType::Uint16 => out.push('q'),
            SigType::Int32 => out.push('i'),
            SigType::Uint32 => out.push('u'),
            SigType::Int64 => out.push('x'),
            SigType::Uint64 => out.push('t'),
            SigType::Double => out.push('d'),
            SigType::Str => out.push('s'),
            SigType::ObjectPath => out.push('o'),
            SigType::Sig => out.push('g'),
            SigType::Variant => out.push('v'),
            SigType::Array(inner) => {
                out.push('a');
                inner.write_code(out);
            }
            SigType::Struct(fields) => {
                out.push('(');
                for f in fields {
                    f.write_code(out);
                }
                out.push(')');
            }
            SigType::DictEntry(k, v) => {
                out.push('{');
                k.write_code(out);
                v.write_code(out);
                out.push('}');
            }
        }
    }

    /// The wire form of this single type.
    pub fn code(&self) -> String {
        let mut s = String::new();
        self.write_code(&mut s);
        s
    }
}

/// Render a sequence of types (as found in a message body) to a signature.
pub fn render_signature(types: &[SigType]) -> String {
    let mut s = String::new();
    for t in types {
        t.write_code(&mut s);
    }
    s
}

/// Parse a complete signature into its top-level types.
///
/// A message body signature is a *sequence*: `"su"` is two arguments, a string
/// and a uint32, not a struct.
pub fn parse_signature(sig: &str) -> Result<Vec<SigType>, DBusError> {
    if sig.len() > MAX_SIGNATURE_LEN {
        return Err(DBusError::protocol(format!(
            "signature of {} bytes exceeds the {MAX_SIGNATURE_LEN} byte limit",
            sig.len()
        )));
    }
    let mut p = SigParser { b: sig.as_bytes(), pos: 0 };
    let mut out = Vec::new();
    while p.pos < p.b.len() {
        out.push(p.parse_one(0, 0)?);
    }
    Ok(out)
}

struct SigParser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl SigParser<'_> {
    fn parse_one(&mut self, array_depth: usize, struct_depth: usize) -> Result<SigType, DBusError> {
        let c = *self.b.get(self.pos).ok_or_else(|| {
            DBusError::protocol("signature ended while a type was still expected")
        })?;
        self.pos += 1;
        let t = match c {
            b'y' => SigType::Byte,
            b'b' => SigType::Boolean,
            b'n' => SigType::Int16,
            b'q' => SigType::Uint16,
            b'i' => SigType::Int32,
            b'u' => SigType::Uint32,
            b'x' => SigType::Int64,
            b't' => SigType::Uint64,
            b'd' => SigType::Double,
            b's' => SigType::Str,
            b'o' => SigType::ObjectPath,
            b'g' => SigType::Sig,
            b'v' => SigType::Variant,
            b'a' => {
                if array_depth + 1 > MAX_ARRAY_DEPTH {
                    return Err(DBusError::protocol(format!(
                        "array nesting deeper than {MAX_ARRAY_DEPTH}"
                    )));
                }
                // A dict entry is only legal as the immediate element type of
                // an array; `{sv}` on its own is not a type.
                if self.b.get(self.pos) == Some(&b'{') {
                    self.pos += 1;
                    let entry = self.parse_dict_entry(array_depth + 1, struct_depth + 1)?;
                    SigType::Array(Box::new(entry))
                } else {
                    SigType::Array(Box::new(self.parse_one(array_depth + 1, struct_depth)?))
                }
            }
            b'(' => {
                if struct_depth + 1 > MAX_STRUCT_DEPTH {
                    return Err(DBusError::protocol(format!(
                        "struct nesting deeper than {MAX_STRUCT_DEPTH}"
                    )));
                }
                let mut fields = Vec::new();
                loop {
                    match self.b.get(self.pos) {
                        None => {
                            return Err(DBusError::protocol("unterminated struct in signature"));
                        }
                        Some(&b')') => {
                            self.pos += 1;
                            break;
                        }
                        Some(_) => fields.push(self.parse_one(array_depth, struct_depth + 1)?),
                    }
                }
                if fields.is_empty() {
                    return Err(DBusError::protocol("empty struct `()` in signature"));
                }
                SigType::Struct(fields)
            }
            b'{' => {
                return Err(DBusError::protocol(
                    "dict entry `{}` outside an array in signature",
                ));
            }
            b')' => return Err(DBusError::protocol("unbalanced `)` in signature")),
            b'}' => return Err(DBusError::protocol("unbalanced `}` in signature")),
            b'h' => {
                // Valid D-Bus, but we never negotiate to receive file
                // descriptors, so accepting it would create a code path that is
                // never exercised and cannot be tested. Reject loudly.
                return Err(DBusError::protocol(
                    "unix fd (`h`) is not supported by this client",
                ));
            }
            other => {
                return Err(DBusError::protocol(format!(
                    "unknown type code `{}` in signature",
                    escape_code(other)
                )));
            }
        };
        Ok(t)
    }

    fn parse_dict_entry(
        &mut self,
        array_depth: usize,
        struct_depth: usize,
    ) -> Result<SigType, DBusError> {
        if struct_depth > MAX_STRUCT_DEPTH {
            return Err(DBusError::protocol(format!(
                "dict entry nesting deeper than {MAX_STRUCT_DEPTH}"
            )));
        }
        let key = self.parse_one(array_depth, struct_depth)?;
        if !key.is_basic() {
            return Err(DBusError::protocol(format!(
                "dict entry key must be a basic type, got `{}`",
                key.code()
            )));
        }
        if self.b.get(self.pos) == Some(&b'}') {
            return Err(DBusError::protocol("dict entry with no value type"));
        }
        let value = self.parse_one(array_depth, struct_depth)?;
        match self.b.get(self.pos) {
            Some(&b'}') => {
                self.pos += 1;
                Ok(SigType::DictEntry(Box::new(key), Box::new(value)))
            }
            Some(_) => Err(DBusError::protocol(
                "dict entry must contain exactly two types",
            )),
            None => Err(DBusError::protocol("unterminated dict entry in signature")),
        }
    }
}

fn escape_code(c: u8) -> String {
    if c.is_ascii_graphic() {
        (c as char).to_string()
    } else {
        format!("\\x{c:02x}")
    }
}
