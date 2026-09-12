//! Minimal, allocation-conscious JSON implementation for the ServerOS agent.
//!
//! Scope is deliberately small: RFC 8259 parsing and serialisation, with the
//! ergonomics the agent actually needs (`json!`-style building, typed getters,
//! and a writer that never emits invalid UTF-8).
//!
//! Deliberate design choices:
//!   * Objects preserve insertion order. API responses are read by humans in
//!     `curl` as often as by the app; stable key order matters.
//!   * Numbers keep their integer-ness. `Value::from(3u64)` round-trips as `3`,
//!     not `3.0` — Swift's `Decodable` is strict about that.
//!   * Parsing is depth-limited and length-limited. The agent parses request
//!     bodies from the network; unbounded recursion is a denial-of-service.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

mod parse;
mod write;

pub use parse::{ParseError, from_slice, from_str};

/// Maximum nesting depth accepted by the parser.
pub const MAX_DEPTH: usize = 64;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Integral number. Kept distinct so round-trips stay integral.
    Int(i64),
    /// Unsigned integral number that may exceed `i64::MAX`.
    UInt(u64),
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// An insertion-ordered JSON object.
///
/// Linear scan on lookup is intentional: agent objects have a handful of keys,
/// and a `Vec` beats a `HashMap` at that size while keeping order for free.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    pub fn new() -> Self {
        Object { entries: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Object { entries: Vec::with_capacity(n) }
    }

    /// Insert, replacing any existing value for `key` in place (order kept).
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        for slot in self.entries.iter_mut() {
            if slot.0 == key {
                slot.1 = value;
                return;
            }
        }
        self.entries.push((key, value));
    }

    /// Builder-style insert, for constructing responses inline.
    #[must_use]
    pub fn set(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.insert(key, value);
        self
    }

    /// Builder-style insert that skips `None`, so optional fields are simply
    /// absent rather than `null`.
    #[must_use]
    pub fn set_opt(mut self, key: impl Into<String>, value: Option<impl Into<Value>>) -> Self {
        if let Some(v) = value {
            self.insert(key, v);
        }
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(idx).1)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl FromIterator<(String, Value)> for Object {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        let mut o = Object::new();
        for (k, v) in iter {
            o.insert(k, v);
        }
        o
    }
}

impl Value {
    pub fn object() -> Object {
        Object::new()
    }

    pub fn array<T: Into<Value>>(items: impl IntoIterator<Item = T>) -> Value {
        Value::Array(items.into_iter().map(Into::into).collect())
    }

    // ---- typed accessors -------------------------------------------------
    // These are intentionally forgiving in one direction only: an Int reads as
    // f64 (widening is lossless enough for our ranges), but a Float never
    // silently reads as an integer.

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::UInt(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt(u) => Some(*u),
            Value::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            Value::UInt(u) => Some(*u as f64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Look up a key on an object value. Returns `None` for non-objects, so
    /// `v.get("a").and_then(|v| v.get("b"))` is safe on malformed input.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }

    /// Follow a slash-separated path: `v.path("Config/Labels")`.
    pub fn path(&self, path: &str) -> Option<&Value> {
        let mut cur = self;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = cur.get(seg)?;
        }
        Some(cur)
    }

    /// Serialise to a compact string.
    ///
    /// Named `encode` rather than `to_string` on purpose: an inherent
    /// `to_string` would shadow the one `Display` provides, and the two could
    /// silently disagree. Callers still get `.to_string()` through `Display`.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(256);
        write::write_value(&mut out, self, None, 0);
        out
    }

    /// Serialise with two-space indentation, for humans and log output.
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::with_capacity(512);
        write::write_value(&mut out, self, Some(2), 0);
        out
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

// ---- From conversions ----------------------------------------------------

impl From<Object> for Value {
    fn from(o: Object) -> Self {
        Value::Object(o)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::String(s.clone())
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        match o {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

macro_rules! from_int {
    ($($t:ty),*) => { $(
        impl From<$t> for Value {
            fn from(v: $t) -> Self { Value::Int(v as i64) }
        }
    )* };
}
from_int!(i8, i16, i32, i64, isize);

macro_rules! from_uint {
    ($($t:ty),*) => { $(
        impl From<$t> for Value {
            fn from(v: $t) -> Self { Value::UInt(v as u64) }
        }
    )* };
}
from_uint!(u8, u16, u32, u64, usize);

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::Float(v as f64)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

impl<V: Into<Value>> From<BTreeMap<String, V>> for Value {
    fn from(m: BTreeMap<String, V>) -> Self {
        let mut o = Object::with_capacity(m.len());
        for (k, v) in m {
            o.insert(k, v);
        }
        Value::Object(o)
    }
}

/// Round a float to `places` decimals before serialising.
///
/// Percentages and rates are the only floats the agent emits. Emitting
/// `23.399999999999999` makes the UI look broken and makes diffs noisy, so
/// every rate goes through here at the edge.
pub fn round(value: f64, places: u32) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    let factor = 10f64.powi(places as i32);
    (value * factor).round() / factor
}

#[cfg(test)]
mod tests;
