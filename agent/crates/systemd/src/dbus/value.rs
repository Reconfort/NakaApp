//! The dynamic value type carried in a D-Bus message body.

use super::DBusError;
use super::signature::SigType;

/// A D-Bus value.
///
/// Deliberately dynamic rather than generic: the agent reads systemd's
/// `a{sv}` property bags, where the value type differs per key and is only
/// known at runtime. A static mapping would be a large amount of code to
/// express "sometimes a uint64, sometimes an array of strings".
#[derive(Debug, Clone, PartialEq)]
pub enum DValue {
    Byte(u8),
    Bool(bool),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    Str(String),
    ObjectPath(String),
    Signature(String),
    Array(Vec<DValue>),
    Struct(Vec<DValue>),
    Variant(Box<DValue>),
    DictEntry(Box<DValue>, Box<DValue>),
}

impl DValue {
    /// Wrap in a variant, for `a{sv}` construction.
    pub fn variant(v: DValue) -> DValue {
        DValue::Variant(Box::new(v))
    }

    /// Convenience constructor for a `DValue::Str`.
    pub fn str(s: impl Into<String>) -> DValue {
        DValue::Str(s.into())
    }

    /// String-ish access. Strings, object paths and signatures all read as
    /// `&str` — the distinction matters on the wire, never to a caller.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            DValue::Str(s) | DValue::ObjectPath(s) | DValue::Signature(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            DValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            DValue::Uint32(v) => Some(*v),
            DValue::Uint16(v) => Some(u32::from(*v)),
            DValue::Byte(v) => Some(u32::from(*v)),
            _ => None,
        }
    }

    /// Widening read of any unsigned integer. systemd is inconsistent about
    /// whether a counter is `u` or `t` across versions, so callers that only
    /// want the number should use this.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            DValue::Uint64(v) => Some(*v),
            DValue::Uint32(v) => Some(u64::from(*v)),
            DValue::Uint16(v) => Some(u64::from(*v)),
            DValue::Byte(v) => Some(u64::from(*v)),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            DValue::Int64(v) => Some(*v),
            DValue::Int32(v) => Some(i64::from(*v)),
            DValue::Int16(v) => Some(i64::from(*v)),
            DValue::Uint32(v) => Some(i64::from(*v)),
            DValue::Uint16(v) => Some(i64::from(*v)),
            DValue::Byte(v) => Some(i64::from(*v)),
            DValue::Uint64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            DValue::Double(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[DValue]> {
        match self {
            DValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&[DValue]> {
        match self {
            DValue::Struct(s) => Some(s),
            _ => None,
        }
    }

    /// Peel one level of variant.
    pub fn as_variant(&self) -> Option<&DValue> {
        match self {
            DValue::Variant(inner) => Some(inner),
            _ => None,
        }
    }

    /// Strip any variant wrapper, returning the value itself otherwise.
    pub fn unwrap_variant(&self) -> &DValue {
        match self {
            DValue::Variant(inner) => inner.unwrap_variant(),
            other => other,
        }
    }

    /// Look up `key` in an `a{sv}` (or any array of dict entries with string
    /// keys), returning the value **with its variant wrapper removed**.
    ///
    /// Every dictionary this crate reads is a `GetAll` property bag, where the
    /// variant is pure protocol noise; making callers unwrap it every time
    /// would be ceremony with no payoff. Use [`DValue::as_variant`] where the
    /// wrapper itself matters.
    pub fn dict_get(&self, key: &str) -> Option<&DValue> {
        let entries = self.as_array()?;
        for e in entries {
            if let DValue::DictEntry(k, v) = e
                && k.as_str() == Some(key)
            {
                return Some(v.unwrap_variant());
            }
        }
        None
    }

    /// Collect an `as` (array of string) into owned strings, skipping any
    /// element that is not string-ish. Returns `None` if this is not an array.
    pub fn as_string_vec(&self) -> Option<Vec<String>> {
        Some(
            self.as_array()?
                .iter()
                .filter_map(|v| v.unwrap_variant().as_str().map(str::to_owned))
                .collect(),
        )
    }

    /// The type code of this value.
    ///
    /// Fails for an empty [`DValue::Array`]: the wire format needs the element
    /// type even when there are no elements, and the value does not carry it.
    /// Callers that marshal an empty array must supply a signature (which every
    /// caller in this crate does — see [`super::marshal::Writer::write_values`]).
    /// The one place we *must* derive a signature from a value is the inside of
    /// a variant, which is why this returns a `Result` rather than panicking.
    pub fn signature(&self) -> Result<SigType, DBusError> {
        Ok(match self {
            DValue::Byte(_) => SigType::Byte,
            DValue::Bool(_) => SigType::Boolean,
            DValue::Int16(_) => SigType::Int16,
            DValue::Uint16(_) => SigType::Uint16,
            DValue::Int32(_) => SigType::Int32,
            DValue::Uint32(_) => SigType::Uint32,
            DValue::Int64(_) => SigType::Int64,
            DValue::Uint64(_) => SigType::Uint64,
            DValue::Double(_) => SigType::Double,
            DValue::Str(_) => SigType::Str,
            DValue::ObjectPath(_) => SigType::ObjectPath,
            DValue::Signature(_) => SigType::Sig,
            DValue::Variant(_) => SigType::Variant,
            DValue::Array(items) => {
                let first = items.first().ok_or_else(|| {
                    DBusError::protocol(
                        "cannot derive a signature for an empty array; supply one explicitly",
                    )
                })?;
                SigType::Array(Box::new(first.signature()?))
            }
            DValue::Struct(fields) => {
                if fields.is_empty() {
                    return Err(DBusError::protocol("cannot marshal a struct with no fields"));
                }
                SigType::Struct(
                    fields.iter().map(DValue::signature).collect::<Result<_, _>>()?,
                )
            }
            DValue::DictEntry(k, v) => {
                SigType::DictEntry(Box::new(k.signature()?), Box::new(v.signature()?))
            }
        })
    }
}

impl From<u8> for DValue {
    fn from(v: u8) -> Self {
        DValue::Byte(v)
    }
}
impl From<bool> for DValue {
    fn from(v: bool) -> Self {
        DValue::Bool(v)
    }
}
impl From<u32> for DValue {
    fn from(v: u32) -> Self {
        DValue::Uint32(v)
    }
}
impl From<u64> for DValue {
    fn from(v: u64) -> Self {
        DValue::Uint64(v)
    }
}
impl From<i32> for DValue {
    fn from(v: i32) -> Self {
        DValue::Int32(v)
    }
}
impl From<i64> for DValue {
    fn from(v: i64) -> Self {
        DValue::Int64(v)
    }
}
impl From<&str> for DValue {
    fn from(v: &str) -> Self {
        DValue::Str(v.to_owned())
    }
}
impl From<String> for DValue {
    fn from(v: String) -> Self {
        DValue::Str(v)
    }
}
