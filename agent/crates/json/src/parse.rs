//! RFC 8259 parser.
//!
//! Hardened for network input: bounded depth, bounded input length, no
//! recursion on arrays/objects beyond `MAX_DEPTH`, and explicit rejection of
//! trailing garbage.

use super::{MAX_DEPTH, Object, Value};
use std::fmt;

/// Largest document the parser will accept (8 MiB).
///
/// The only large bodies the agent receives are file uploads, and those use a
/// raw binary body rather than JSON.
pub const MAX_INPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn from_str(s: &str) -> Result<Value, ParseError> {
    from_slice(s.as_bytes())
}

pub fn from_slice(input: &[u8]) -> Result<Value, ParseError> {
    if input.len() > MAX_INPUT {
        return Err(ParseError { message: format!("document exceeds {MAX_INPUT} bytes"), offset: 0 });
    }
    let mut p = Parser { input, pos: 0, depth: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(p.err("unexpected trailing data"));
    }
    Ok(v)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: impl Into<String>) -> ParseError {
        ParseError { message: msg.into(), offset: self.pos }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(format!("expected '{}'", b as char)))
        }
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(c) => Err(self.err(format!("unexpected character '{}'", c as char))),
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, ParseError> {
        if self.input[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err(format!("nesting deeper than {MAX_DEPTH}")));
        }
        Ok(())
    }

    fn array(&mut self) -> Result<Value, ParseError> {
        self.enter()?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => {
                    self.pos = self.pos.saturating_sub(1);
                    return Err(self.err("expected ',' or ']'"));
                }
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn object(&mut self) -> Result<Value, ParseError> {
        self.enter()?;
        self.expect(b'{')?;
        let mut obj = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Object(obj));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key"));
            }
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.value()?;
            obj.insert(key, val);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => {
                    self.pos = self.pos.saturating_sub(1);
                    return Err(self.err("expected ',' or '}'"));
                }
            }
        }
        self.depth -= 1;
        Ok(Value::Object(obj))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or_else(|| self.err("unterminated string"))?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.bump().ok_or_else(|| self.err("unterminated escape"))?;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.err("invalid escape sequence")),
                    }
                }
                0x00..=0x1F => return Err(self.err("unescaped control character in string")),
                _ => {
                    // Re-decode the UTF-8 sequence starting at this byte.
                    let start = self.pos - 1;
                    let len = utf8_len(b).ok_or_else(|| self.err("invalid UTF-8 start byte"))?;
                    if start + len > self.input.len() {
                        return Err(self.err("truncated UTF-8 sequence"));
                    }
                    let chunk = &self.input[start..start + len];
                    let s = std::str::from_utf8(chunk).map_err(|_| self.err("invalid UTF-8"))?;
                    out.push_str(s);
                    self.pos = start + len;
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let hi = self.hex4()?;
        // Surrogate pair handling: a high surrogate must be followed by \uDC00-\uDFFF.
        if (0xD800..0xDC00).contains(&hi) {
            if self.input[self.pos..].starts_with(b"\\u") {
                self.pos += 2;
                let lo = self.hex4()?;
                if (0xDC00..0xE000).contains(&lo) {
                    let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return char::from_u32(c).ok_or_else(|| self.err("invalid code point"));
                }
                return Err(self.err("invalid low surrogate"));
            }
            return Err(self.err("lone high surrogate"));
        }
        if (0xDC00..0xE000).contains(&hi) {
            return Err(self.err("lone low surrogate"));
        }
        char::from_u32(hi).ok_or_else(|| self.err("invalid code point"))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| self.err("truncated \\u escape"))?;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(self.err("invalid hex digit")),
            };
            v = (v << 4) | d as u32;
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // Integer part: either a single 0 or [1-9][0-9]*
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.err("expected digit")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit after '.'"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit in exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| self.err("invalid number encoding"))?;

        if !is_float {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(Value::Int(i));
            }
            if let Ok(u) = text.parse::<u64>() {
                return Ok(Value::UInt(u));
            }
            // Integer too large for 64 bits: fall through to f64 rather than
            // failing. Docker reports some sizes as very large integers.
        }
        text.parse::<f64>().map(Value::Float).map_err(|_| self.err("number out of range"))
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}
