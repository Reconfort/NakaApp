//! Serialisation.
//!
//! Two rules that matter downstream:
//!   * Non-finite floats become `null`, never `NaN`/`Infinity` (which are not
//!     JSON and would make Swift's `JSONDecoder` throw).
//!   * `/` is not escaped, but `<`, `>` and `&` are left as-is too — the agent
//!     never emits JSON into an HTML context.

use super::Value;

pub fn write_value(out: &mut String, v: &Value, indent: Option<usize>, level: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::UInt(u) => out.push_str(&u.to_string()),
        Value::Float(f) => write_float(out, *f),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(out, indent, level + 1);
                write_value(out, item, indent, level + 1);
            }
            newline_indent(out, indent, level);
            out.push(']');
        }
        Value::Object(obj) => {
            if obj.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in obj.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(out, indent, level + 1);
                write_string(out, k);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(out, val, indent, level + 1);
            }
            newline_indent(out, indent, level);
            out.push('}');
        }
    }
}

fn newline_indent(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        for _ in 0..(width * level) {
            out.push(' ');
        }
    }
}

fn write_float(out: &mut String, f: f64) {
    if !f.is_finite() {
        out.push_str("null");
        return;
    }
    if f == f.trunc() && f.abs() < 1e15 {
        // Emit `1.0` rather than `1` so the value stays a JSON number that
        // Swift decodes as Double without ambiguity, but keep it short.
        out.push_str(&format!("{f:.1}"));
    } else {
        // `{}` on f64 produces the shortest representation that round-trips.
        out.push_str(&f.to_string());
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            // U+2028/U+2029 are valid JSON but break naive JS eval; escape them
            // because the control plane forwards agent JSON to a browser.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}
