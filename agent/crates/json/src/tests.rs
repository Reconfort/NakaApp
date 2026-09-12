use super::*;

fn p(s: &str) -> Value {
    from_str(s).unwrap_or_else(|e| panic!("parse {s:?} failed: {e}"))
}

#[test]
fn parses_scalars() {
    assert_eq!(p("null"), Value::Null);
    assert_eq!(p("true"), Value::Bool(true));
    assert_eq!(p("false"), Value::Bool(false));
    assert_eq!(p("0"), Value::Int(0));
    assert_eq!(p("-17"), Value::Int(-17));
    assert_eq!(p("1.5"), Value::Float(1.5));
    assert_eq!(p("1e3"), Value::Float(1000.0));
    assert_eq!(p("-2.5E-2"), Value::Float(-0.025));
    assert_eq!(p(r#""hi""#), Value::String("hi".into()));
}

#[test]
fn keeps_integers_integral() {
    // Regression: a naive parser stores everything as f64 and then 3 serialises
    // as 3.0, which breaks `Int` decoding on the Swift side.
    assert_eq!(p("3").to_string(), "3");
    assert_eq!(Value::from(3u64).to_string(), "3");
    assert_eq!(Value::from(3.0f64).to_string(), "3.0");
}

#[test]
fn integers_beyond_i64_survive() {
    let v = p("18446744073709551615");
    assert_eq!(v.as_u64(), Some(u64::MAX));
    assert_eq!(v.to_string(), "18446744073709551615");
}

#[test]
fn parses_nested_structures() {
    let v = p(r#"{"a":[1,2,{"b":null}],"c":{"d":true}}"#);
    assert_eq!(v.path("a").unwrap().as_array().unwrap().len(), 3);
    assert_eq!(v.path("c/d").unwrap().as_bool(), Some(true));
    assert!(v.path("a/0").is_none(), "path only walks objects");
}

#[test]
fn string_escapes_round_trip() {
    let raw = "quote\" backslash\\ newline\n tab\t control\u{1} unicode\u{263A} astral\u{1F600}";
    let encoded = Value::from(raw).to_string();
    assert_eq!(p(&encoded).as_str(), Some(raw));
}

#[test]
fn parses_surrogate_pairs() {
    assert_eq!(p(r#""\uD83D\uDE00""#).as_str(), Some("\u{1F600}"));
    assert_eq!(p(r#""\u0041""#).as_str(), Some("A"));
}

#[test]
fn rejects_malformed_input() {
    let bad = [
        "",
        "{",
        "[1,]",
        "{\"a\":}",
        "{a:1}",
        "01",
        "1.",
        ".5",
        "+1",
        "nul",
        "\"unterminated",
        "\"\\q\"",
        "{} junk",
        "\"\\uD800\"",       // lone high surrogate
        "\"\\uDC00\"",       // lone low surrogate
        "\"raw\ncontrol\"",  // unescaped control char
    ];
    for case in bad {
        assert!(from_str(case).is_err(), "expected {case:?} to be rejected");
    }
}

#[test]
fn enforces_depth_limit() {
    let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
    let err = from_str(&deep).unwrap_err();
    assert!(err.message.contains("nesting"), "got {err}");

    let ok = "[".repeat(MAX_DEPTH - 1) + &"]".repeat(MAX_DEPTH - 1);
    assert!(from_str(&ok).is_ok());
}

#[test]
fn enforces_input_limit() {
    let huge = vec![b' '; parse::MAX_INPUT + 1];
    assert!(from_slice(&huge).is_err());
}

#[test]
fn object_preserves_insertion_order_and_replaces_in_place() {
    let mut o = Object::new();
    o.insert("z", 1);
    o.insert("a", 2);
    o.insert("z", 3);
    assert_eq!(Value::Object(o).to_string(), r#"{"z":3,"a":2}"#);
}

#[test]
fn set_opt_omits_none() {
    let o = Object::new()
        .set("always", 1)
        .set_opt("present", Some("x"))
        .set_opt("absent", Option::<String>::None);
    assert_eq!(Value::Object(o).to_string(), r#"{"always":1,"present":"x"}"#);
}

#[test]
fn non_finite_floats_become_null() {
    // JSON has no NaN/Infinity. A CPU percentage computed from a zero-length
    // sample interval used to emit NaN and break the decoder.
    assert_eq!(Value::from(f64::NAN).to_string(), "null");
    assert_eq!(Value::from(f64::INFINITY).to_string(), "null");
    assert_eq!(round(f64::NAN, 2), 0.0);
}

#[test]
fn rounding_trims_float_noise() {
    assert_eq!(round(23.39999999999, 1), 23.4);
    assert_eq!(round(0.1 + 0.2, 2), 0.3);
    assert_eq!(Value::from(round(66.66666, 2)).to_string(), "66.67");
}

#[test]
fn pretty_printing_is_parseable() {
    let v = p(r#"{"a":[1,{"b":"c"}],"d":{}}"#);
    let pretty = v.to_string_pretty();
    assert!(pretty.contains('\n'));
    assert_eq!(p(&pretty), v);
}

#[test]
fn empty_containers_stay_compact_when_pretty() {
    let v = p(r#"{"a":[],"b":{}}"#);
    assert_eq!(v.to_string_pretty(), "{\n  \"a\": [],\n  \"b\": {}\n}");
}

#[test]
fn typed_accessors_do_not_coerce_wrongly() {
    assert_eq!(p("1.5").as_i64(), None, "floats must not read as integers");
    assert_eq!(p("-1").as_u64(), None, "negatives must not read as unsigned");
    assert_eq!(p("7").as_f64(), Some(7.0), "ints widen to float");
    assert_eq!(p(r#""7""#).as_i64(), None, "strings are not numbers");
}

#[test]
fn get_on_non_object_is_none_not_panic() {
    assert!(p("[1]").get("a").is_none());
    assert!(p("null").path("a/b/c").is_none());
}

#[test]
fn line_separators_are_escaped() {
    // U+2028 inside a JSON string is legal but breaks naive JS parsers in the
    // control plane's browser console.
    assert_eq!(Value::from("a\u{2028}b").to_string(), r#""a\u2028b""#);
}

#[test]
fn parses_a_realistic_docker_payload() {
    let src = r#"[{"Id":"abc123","Names":["/serveros-test"],"Image":"nginx:alpine",
        "State":"running","Status":"Up 2 hours","Created":1757635200,
        "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],
        "Labels":{"com.docker.compose.project":"estatify"}}]"#;
    let v = p(src);
    let c = &v.as_array().unwrap()[0];
    assert_eq!(c.get("Id").unwrap().as_str(), Some("abc123"));
    assert_eq!(c.path("Ports").unwrap().as_array().unwrap()[0].get("PublicPort").unwrap().as_u64(), Some(8080));
    assert_eq!(c.path("Labels/com.docker.compose.project").unwrap().as_str(), Some("estatify"));
}
