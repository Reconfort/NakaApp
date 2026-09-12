//! Unit tests.
//!
//! The byte-exact assertions here are hand-verified against the D-Bus
//! specification's marshalling rules rather than against our own output: a
//! round-trip test proves self-consistency and nothing else. The live tests in
//! `tests/live_dbus.rs` check the same codec against `dbus-daemon`, which is
//! the part that actually proves interoperability.

use std::collections::BTreeMap;

use crate::dbus::marshal::{Endian, Reader, Writer, validate_object_path};
use crate::dbus::message::{FIXED_HEADER_LEN, MAX_MESSAGE_SIZE, Message, MessageType};
use crate::dbus::signature::{SigType, parse_signature, render_signature};
use crate::dbus::transport::{BusAddress, hex_encode, parse_address};
use crate::dbus::{DBusError, DValue};
use crate::names::{display_name, is_interesting_service, unit_suffix, validate_unit_name};
use crate::systemd::{parse_key_values, parse_list_units_table};
use crate::unit::{Unit, UnitDetail, rollup_state, units_json};

// ------------------------------------------------------------------ helpers

/// Marshal `values` against `sig` and return the bytes.
fn marshal(sig: &str, values: &[DValue]) -> Vec<u8> {
    let types = parse_signature(sig).expect("signature should parse");
    let mut w = Writer::new(Endian::Little);
    w.write_values(&types, values).expect("values should marshal");
    w.into_bytes()
}

/// Marshal then unmarshal, asserting the values survive.
fn round_trip(sig: &str, values: Vec<DValue>) -> Vec<u8> {
    let bytes = marshal(sig, &values);
    let types = parse_signature(sig).unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    let back = r.read_values(&types).expect("values should unmarshal");
    assert_eq!(back, values, "round-trip mismatch for signature `{sig}`");
    assert_eq!(r.remaining(), 0, "trailing bytes after reading `{sig}`");
    bytes
}

// -------------------------------------------------------- signature parsing

#[test]
fn signature_parses_every_basic_type() {
    let sig = "ybnqiuxtdsogv";
    let types = parse_signature(sig).unwrap();
    assert_eq!(types.len(), 13);
    assert_eq!(render_signature(&types), sig);
}

#[test]
fn signature_parses_list_units_reply() {
    let types = parse_signature("a(ssssssouso)").unwrap();
    assert_eq!(types.len(), 1);
    let SigType::Array(elem) = &types[0] else { panic!("expected an array") };
    let SigType::Struct(fields) = elem.as_ref() else { panic!("expected a struct") };
    assert_eq!(fields.len(), 10);
    assert_eq!(fields[6], SigType::ObjectPath);
    assert_eq!(fields[7], SigType::Uint32);
    assert_eq!(render_signature(&types), "a(ssssssouso)");
}

#[test]
fn signature_parses_property_dictionary() {
    let types = parse_signature("a{sv}").unwrap();
    let SigType::Array(elem) = &types[0] else { panic!("expected an array") };
    assert!(matches!(elem.as_ref(), SigType::DictEntry(k, v)
        if **k == SigType::Str && **v == SigType::Variant));
    assert_eq!(render_signature(&types), "a{sv}");
}

#[test]
fn signature_parses_nested_struct_with_dictionary() {
    let types = parse_signature("(ia{sv}v)").unwrap();
    assert_eq!(types.len(), 1);
    let SigType::Struct(fields) = &types[0] else { panic!("expected a struct") };
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], SigType::Int32);
    assert_eq!(fields[2], SigType::Variant);
    assert_eq!(render_signature(&types), "(ia{sv}v)");
}

#[test]
fn signature_parses_nested_arrays() {
    let types = parse_signature("aaai").unwrap();
    assert_eq!(render_signature(&types), "aaai");
    assert_eq!(types[0].alignment(), 4, "an array is always 4-aligned");
}

#[test]
fn signature_parses_a_body_of_several_arguments() {
    // "asbb" is EnableUnitFiles: not one struct, four separate arguments.
    let types = parse_signature("asbb").unwrap();
    assert_eq!(types.len(), 3);
    assert_eq!(types[0], SigType::Array(Box::new(SigType::Str)));
    assert_eq!(types[1], SigType::Boolean);
}

#[test]
fn signature_rejects_unbalanced_parens() {
    assert!(parse_signature("(si").is_err());
    assert!(parse_signature("si)").is_err());
    assert!(parse_signature("((s)").is_err());
}

#[test]
fn signature_rejects_unbalanced_braces() {
    assert!(parse_signature("a{sv").is_err());
    assert!(parse_signature("sv}").is_err());
}

#[test]
fn signature_rejects_unknown_type_code() {
    let e = parse_signature("sZu").unwrap_err();
    assert!(format!("{e}").contains("unknown type code"), "got: {e}");
}

#[test]
fn signature_rejects_empty_struct() {
    assert!(parse_signature("()").is_err());
}

#[test]
fn signature_rejects_dict_entry_outside_an_array() {
    assert!(parse_signature("{sv}").is_err());
    assert!(parse_signature("({sv})").is_err());
}

#[test]
fn signature_rejects_dict_entry_with_a_container_key() {
    assert!(parse_signature("a{(s)v}").is_err());
    assert!(parse_signature("a{vs}").is_err());
}

#[test]
fn signature_rejects_dict_entry_with_wrong_arity() {
    assert!(parse_signature("a{s}").is_err());
    assert!(parse_signature("a{svv}").is_err());
}

#[test]
fn signature_rejects_over_deep_nesting() {
    let deep = "a".repeat(40) + "i";
    let e = parse_signature(&deep).unwrap_err();
    assert!(format!("{e}").contains("array nesting"), "got: {e}");

    let deep_struct = "(".repeat(40) + "i" + &")".repeat(40);
    assert!(parse_signature(&deep_struct).is_err());
}

#[test]
fn signature_rejects_an_over_long_signature() {
    let long = "y".repeat(256);
    assert!(parse_signature(&long).is_err());
}

#[test]
fn signature_rejects_unix_fd_because_we_never_negotiate_one() {
    let e = parse_signature("h").unwrap_err();
    assert!(format!("{e}").contains("unix fd"), "got: {e}");
}

#[test]
fn signature_alignments_match_the_specification() {
    let cases: &[(&str, usize)] = &[
        ("y", 1),
        ("g", 1),
        ("v", 1),
        ("n", 2),
        ("q", 2),
        ("b", 4),
        ("i", 4),
        ("u", 4),
        ("s", 4),
        ("o", 4),
        ("ai", 4),
        ("x", 8),
        ("t", 8),
        ("d", 8),
        ("(y)", 8),
    ];
    for (sig, want) in cases {
        let t = parse_signature(sig).unwrap();
        assert_eq!(t[0].alignment(), *want, "alignment of `{sig}`");
    }
}

// ------------------------------------------------------- marshalling: bytes

#[test]
fn marshal_byte_then_uint32_inserts_three_padding_bytes() {
    // `y` is 1-aligned so the byte lands at 0; `u` is 4-aligned so it must
    // start at 4, leaving three zero bytes behind it.
    let bytes = round_trip("yu", vec![DValue::Byte(1), DValue::Uint32(2)]);
    assert_eq!(bytes, vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn marshal_byte_then_uint64_inserts_seven_padding_bytes() {
    let bytes = round_trip("yt", vec![DValue::Byte(0xff), DValue::Uint64(1)]);
    assert_eq!(bytes.len(), 16);
    assert_eq!(&bytes[1..8], &[0u8; 7], "padding must be zero");
    assert_eq!(&bytes[8..16], &1u64.to_le_bytes());
}

#[test]
fn marshal_string_is_length_bytes_nul() {
    let bytes = round_trip("s", vec![DValue::str("foo")]);
    assert_eq!(bytes, vec![0x03, 0x00, 0x00, 0x00, b'f', b'o', b'o', 0x00]);
}

#[test]
fn marshal_empty_string_still_has_a_nul() {
    let bytes = round_trip("s", vec![DValue::str("")]);
    assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn marshal_signature_uses_a_single_byte_length() {
    // This is why `g` has alignment 1: its length prefix is a u8.
    let bytes = round_trip("g", vec![DValue::Signature("a{sv}".to_owned())]);
    assert_eq!(bytes, vec![0x05, b'a', b'{', b's', b'v', b'}', 0x00]);
}

#[test]
fn marshal_empty_array_still_pads_to_the_element_alignment() {
    // The length is zero, but `t` is 8-aligned, so four bytes of padding sit
    // between the length and where the (absent) first element would be.
    let bytes = round_trip("at", vec![DValue::Array(vec![])]);
    assert_eq!(bytes, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(bytes.len(), 8);
}

#[test]
fn marshal_empty_array_of_bytes_needs_no_padding() {
    let bytes = round_trip("ay", vec![DValue::Array(vec![])]);
    assert_eq!(bytes, vec![0, 0, 0, 0], "`y` is 1-aligned, so no padding");
}

#[test]
fn marshal_array_length_excludes_its_own_padding() {
    // a(su) with one element ("a", 1):
    //   0..4   array byte length = 12
    //   4..8   padding to the struct's 8-byte alignment (NOT counted)
    //   8..12  string length 1
    //   12..14 'a', NUL
    //   14..16 padding to `u`'s 4-byte alignment
    //   16..20 uint32 1
    let bytes = round_trip(
        "a(su)",
        vec![DValue::Array(vec![DValue::Struct(vec![
            DValue::str("a"),
            DValue::Uint32(1),
        ])])],
    );
    assert_eq!(bytes.len(), 20);
    assert_eq!(&bytes[0..4], &12u32.to_le_bytes(), "length covers only element data");
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0], "struct alignment padding");
    assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &[b'a', 0, 0, 0]);
    assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
}

#[test]
fn marshal_dictionary_aligns_entries_to_eight() {
    // a{sv} with {"Id": <"nginx.service">}, verified by hand against the spec:
    //   0..4   array length = 30
    //   4..8   padding to the dict entry's 8-byte alignment
    //   8..12  key length 2
    //   12..15 "Id\0"
    //   15..18 variant signature: len 1, 's', NUL
    //   18..20 padding to the string's 4-byte alignment
    //   20..24 value length 13
    //   24..38 "nginx.service\0"
    let value = DValue::Array(vec![DValue::DictEntry(
        Box::new(DValue::str("Id")),
        Box::new(DValue::variant(DValue::str("nginx.service"))),
    )]);
    let bytes = round_trip("a{sv}", vec![value]);
    assert_eq!(bytes.len(), 38);
    assert_eq!(&bytes[0..4], &30u32.to_le_bytes());
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
    assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
    assert_eq!(&bytes[12..15], b"Id\0");
    assert_eq!(&bytes[15..18], &[0x01, b's', 0x00]);
    assert_eq!(&bytes[18..20], &[0, 0]);
    assert_eq!(&bytes[20..24], &13u32.to_le_bytes());
    assert_eq!(&bytes[24..38], b"nginx.service\0");
}

#[test]
fn marshal_struct_inside_array_inside_struct() {
    // (a(iu)s): the inner struct re-aligns to 8 inside the array, and the
    // trailing string re-aligns to 4 after it.
    let value = DValue::Struct(vec![
        DValue::Array(vec![
            DValue::Struct(vec![DValue::Int32(-1), DValue::Uint32(7)]),
            DValue::Struct(vec![DValue::Int32(2), DValue::Uint32(8)]),
        ]),
        DValue::str("end"),
    ]);
    let bytes = round_trip("(a(iu)s)", vec![value]);
    // 0..4 array length, 4..8 pad, 8..16 first struct, 16..24 second struct,
    // 24..28 string length, 28..32 "end\0".
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes[0..4], &16u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &(-1i32).to_le_bytes());
    assert_eq!(&bytes[24..28], &3u32.to_le_bytes());
    assert_eq!(&bytes[28..32], b"end\0");
}

#[test]
fn marshal_bool_is_a_uint32() {
    let bytes = round_trip("bb", vec![DValue::Bool(true), DValue::Bool(false)]);
    assert_eq!(bytes, vec![1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn unmarshal_rejects_a_bool_that_is_not_zero_or_one() {
    let bytes = 2u32.to_le_bytes();
    let types = parse_signature("b").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    let e = r.read_values(&types).unwrap_err();
    assert!(format!("{e}").contains("boolean"), "got: {e}");
}

// ----------------------------------------------- marshalling: every type

#[test]
fn round_trip_every_integer_type() {
    round_trip("y", vec![DValue::Byte(0xab)]);
    round_trip("n", vec![DValue::Int16(-31_000)]);
    round_trip("q", vec![DValue::Uint16(65_535)]);
    round_trip("i", vec![DValue::Int32(i32::MIN)]);
    round_trip("u", vec![DValue::Uint32(u32::MAX)]);
    round_trip("x", vec![DValue::Int64(i64::MIN)]);
    round_trip("t", vec![DValue::Uint64(u64::MAX)]);
}

#[test]
fn round_trip_double() {
    let bytes = round_trip("d", vec![DValue::Double(-1.5)]);
    assert_eq!(bytes, (-1.5f64).to_bits().to_le_bytes());
}

#[test]
fn round_trip_object_path() {
    round_trip(
        "o",
        vec![DValue::ObjectPath("/org/freedesktop/systemd1/unit/nginx_2eservice".to_owned())],
    );
}

#[test]
fn round_trip_variant_of_array_of_strings() {
    round_trip(
        "v",
        vec![DValue::variant(DValue::Array(vec![
            DValue::str("man:nginx(8)"),
            DValue::str("https://nginx.org/en/docs/"),
        ]))],
    );
}

#[test]
fn round_trip_nested_arrays() {
    round_trip(
        "aai",
        vec![DValue::Array(vec![
            DValue::Array(vec![DValue::Int32(1), DValue::Int32(2)]),
            DValue::Array(vec![]),
            DValue::Array(vec![DValue::Int32(3)]),
        ])],
    );
}

#[test]
fn round_trip_a_full_list_units_element() {
    let elem = DValue::Struct(vec![
        DValue::str("nginx.service"),
        DValue::str("A high performance web server"),
        DValue::str("loaded"),
        DValue::str("active"),
        DValue::str("running"),
        DValue::str(""),
        DValue::ObjectPath("/org/freedesktop/systemd1/unit/nginx_2eservice".to_owned()),
        DValue::Uint32(0),
        DValue::str(""),
        DValue::ObjectPath("/".to_owned()),
    ]);
    round_trip("a(ssssssouso)", vec![DValue::Array(vec![elem])]);
}

#[test]
fn round_trip_big_endian() {
    let types = parse_signature("us").unwrap();
    let values = vec![DValue::Uint32(0x0102_0304), DValue::str("hi")];
    let mut w = Writer::new(Endian::Big);
    w.write_values(&types, &values).unwrap();
    let bytes = w.into_bytes();
    assert_eq!(&bytes[0..4], &[0x01, 0x02, 0x03, 0x04], "big-endian byte order");
    let mut r = Reader::new(&bytes, Endian::Big);
    assert_eq!(r.read_values(&types).unwrap(), values);
}

#[test]
fn marshal_rejects_a_value_of_the_wrong_type() {
    let types = parse_signature("u").unwrap();
    let mut w = Writer::new(Endian::Little);
    let e = w.write_value(&types[0], &DValue::str("not a number")).unwrap_err();
    assert!(format!("{e}").contains("cannot marshal"), "got: {e}");
}

#[test]
fn marshal_rejects_an_arity_mismatch() {
    let types = parse_signature("us").unwrap();
    let mut w = Writer::new(Endian::Little);
    assert!(w.write_values(&types, &[DValue::Uint32(1)]).is_err());
}

#[test]
fn marshal_rejects_an_embedded_nul_in_a_string() {
    let types = parse_signature("s").unwrap();
    let mut w = Writer::new(Endian::Little);
    assert!(w.write_value(&types[0], &DValue::Str("a\0b".to_owned())).is_err());
}

#[test]
fn marshal_rejects_an_empty_array_inside_a_variant() {
    // The variant must carry an inner signature, and an empty array cannot
    // supply one. Better a clear error than a guess.
    let types = parse_signature("v").unwrap();
    let mut w = Writer::new(Endian::Little);
    let e = w
        .write_value(&types[0], &DValue::variant(DValue::Array(vec![])))
        .unwrap_err();
    assert!(format!("{e}").contains("empty array"), "got: {e}");
}

#[test]
fn unmarshal_rejects_non_zero_padding() {
    // Same as `marshal_byte_then_uint32...`, but with a junk byte in the pad.
    let bytes = [0x01, 0xff, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    let types = parse_signature("yu").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    let e = r.read_values(&types).unwrap_err();
    assert!(format!("{e}").contains("non-zero alignment padding"), "got: {e}");
}

#[test]
fn unmarshal_rejects_a_truncated_value() {
    let bytes = [0x04, 0x00, 0x00, 0x00, b'a', b'b'];
    let types = parse_signature("s").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert!(r.read_values(&types).is_err());
}

#[test]
fn unmarshal_rejects_a_string_that_is_not_nul_terminated() {
    let bytes = [0x02, 0x00, 0x00, 0x00, b'a', b'b', b'c'];
    let types = parse_signature("s").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    let e = r.read_values(&types).unwrap_err();
    assert!(format!("{e}").contains("NUL-terminated"), "got: {e}");
}

#[test]
fn unmarshal_rejects_invalid_utf8() {
    let bytes = [0x02, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00];
    let types = parse_signature("s").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    let e = r.read_values(&types).unwrap_err();
    assert!(format!("{e}").contains("UTF-8"), "got: {e}");
}

#[test]
fn unmarshal_rejects_an_array_whose_element_overruns_its_length() {
    // Declared length 4, but a struct element consumes 8.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]); // pad to 8
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    let types = parse_signature("a(uu)").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert!(r.read_values(&types).is_err());
}

#[test]
fn unmarshal_rejects_an_absurd_array_length() {
    let bytes = u32::MAX.to_le_bytes();
    let types = parse_signature("ay").unwrap();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert!(matches!(r.read_values(&types), Err(DBusError::TooLarge { .. })));
}

#[test]
fn object_path_validation() {
    for good in ["/", "/org/freedesktop/DBus", "/a", "/a_1/b2"] {
        assert!(validate_object_path(good).is_ok(), "{good} should be valid");
    }
    for bad in ["", "org/freedesktop", "/org//freedesktop", "/org/", "/org/free-desktop"] {
        assert!(validate_object_path(bad).is_err(), "{bad:?} should be invalid");
    }
}

// ---------------------------------------------------------------- messages

fn hello() -> Message {
    let mut m = Message::method_call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
    );
    m.serial = 1;
    m
}

#[test]
fn method_call_round_trips() {
    let msg = hello();
    let bytes = msg.to_bytes().unwrap();
    let back = Message::parse(&bytes).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn method_call_fixed_header_matches_the_specification() {
    let bytes = hello().to_bytes().unwrap();
    assert_eq!(bytes[0], b'l', "little-endian");
    assert_eq!(bytes[1], 1, "METHOD_CALL");
    assert_eq!(bytes[2], 0, "no flags");
    assert_eq!(bytes[3], 1, "protocol version 1");
    assert_eq!(&bytes[4..8], &0u32.to_le_bytes(), "empty body");
    assert_eq!(&bytes[8..12], &1u32.to_le_bytes(), "serial 1");
    assert_eq!(FIXED_HEADER_LEN, 12);
}

#[test]
fn message_length_accounting_is_self_consistent() {
    let msg = Message::method_call("a.b", "/c", "d.e", "F")
        .with_body("s", vec![DValue::str("payload")]);
    let mut msg = msg;
    msg.serial = 9;
    let bytes = msg.to_bytes().unwrap();
    // The one place the `align8(16 + fields) + body` expression lives must
    // agree with what the writer actually produced.
    assert_eq!(Message::expected_len(&bytes).unwrap(), Some(bytes.len()));
    // "payload" marshals to 4 length bytes + 7 + NUL = 12.
    assert_eq!(bytes.len() % 8, 4);
}

#[test]
fn message_body_starts_on_an_eight_byte_boundary() {
    let mut msg =
        Message::method_call("a.b", "/c", "d.e", "F").with_body("y", vec![DValue::Byte(0x7f)]);
    msg.serial = 3;
    let bytes = msg.to_bytes().unwrap();
    let body_start = bytes.len() - 1;
    assert_eq!(body_start % 8, 0, "body must begin 8-aligned");
    assert_eq!(bytes[body_start], 0x7f);
}

#[test]
fn method_call_with_a_body_round_trips() {
    let mut msg = Message::method_call(
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartUnit",
    )
    .with_body("ss", vec![DValue::str("nginx.service"), DValue::str("replace")]);
    msg.serial = 42;
    let bytes = msg.to_bytes().unwrap();
    let back = Message::parse(&bytes).unwrap();
    assert_eq!(back.member.as_deref(), Some("StartUnit"));
    assert_eq!(back.signature.as_deref(), Some("ss"));
    assert_eq!(back.body[0].as_str(), Some("nginx.service"));
    assert_eq!(back.body[1].as_str(), Some("replace"));
}

#[test]
fn error_message_round_trips_and_exposes_its_text() {
    let call = hello();
    let mut err = Message::error_reply(
        &call,
        "org.freedesktop.systemd1.NoSuchUnit",
        "Unit nope.service not found.",
    );
    err.serial = 7;
    err.sender = Some(":1.0".to_owned());
    let bytes = err.to_bytes().unwrap();
    let back = Message::parse(&bytes).unwrap();
    assert_eq!(back.kind, MessageType::Error);
    assert_eq!(back.error_name.as_deref(), Some("org.freedesktop.systemd1.NoSuchUnit"));
    assert_eq!(back.reply_serial, Some(1));
    assert_eq!(back.error_text(), "Unit nope.service not found.");
}

#[test]
fn method_return_round_trips() {
    let mut call = hello();
    call.sender = Some(":1.5".to_owned());
    let mut ret = Message::method_return(&call).with_body("s", vec![DValue::str(":1.5")]);
    ret.serial = 2;
    let back = Message::parse(&ret.to_bytes().unwrap()).unwrap();
    assert_eq!(back.kind, MessageType::MethodReturn);
    assert_eq!(back.reply_serial, Some(1));
    assert_eq!(back.destination.as_deref(), Some(":1.5"));
}

#[test]
fn message_round_trips_big_endian() {
    let mut msg = Message::method_call("a.b", "/c", "d.e", "F")
        .with_body("u", vec![DValue::Uint32(0x0a0b_0c0d)]);
    msg.serial = 11;
    let bytes = msg.to_bytes_endian(Endian::Big).unwrap();
    assert_eq!(bytes[0], b'B');
    let back = Message::parse(&bytes).unwrap();
    assert_eq!(back.body[0].as_u32(), Some(0x0a0b_0c0d));
}

#[test]
fn message_rejects_a_wrong_protocol_version() {
    let mut bytes = hello().to_bytes().unwrap();
    bytes[3] = 2;
    let e = Message::parse(&bytes).unwrap_err();
    assert!(format!("{e}").contains("protocol version"), "got: {e}");
}

#[test]
fn message_rejects_a_bad_endianness_byte() {
    let mut bytes = hello().to_bytes().unwrap();
    bytes[0] = b'x';
    assert!(Message::parse(&bytes).is_err());
}

#[test]
fn message_rejects_a_body_larger_than_the_cap() {
    let mut bytes = hello().to_bytes().unwrap();
    bytes[4..8].copy_from_slice(&(MAX_MESSAGE_SIZE as u32 + 1).to_le_bytes());
    let e = Message::parse(&bytes).unwrap_err();
    assert!(matches!(e, DBusError::TooLarge { .. }), "got: {e}");
}

#[test]
fn message_rejects_a_zero_serial() {
    let mut msg = hello();
    msg.serial = 0;
    assert!(msg.to_bytes().is_err());
}

#[test]
fn message_rejects_a_truncated_header() {
    assert!(Message::parse(&[b'l', 1, 0, 1]).is_err());
    assert_eq!(Message::expected_len(&[b'l', 1, 0, 1]).unwrap(), None);
}

#[test]
fn message_rejects_a_method_call_with_no_member() {
    let mut msg = hello();
    msg.member = None;
    let bytes = msg.to_bytes().unwrap();
    let e = Message::parse(&bytes).unwrap_err();
    assert!(format!("{e}").contains("MEMBER"), "got: {e}");
}

#[test]
fn message_rejects_an_error_with_no_error_name() {
    let mut msg = Message::error_reply(&hello(), "x.Y", "boom");
    msg.error_name = None;
    msg.serial = 4;
    let bytes = msg.to_bytes().unwrap();
    assert!(Message::parse(&bytes).is_err());
}

#[test]
fn message_ignores_unknown_header_fields() {
    // Field code 200 does not exist. Ignoring it is what keeps the protocol
    // extensible; rejecting it would break against a future bus.
    let mut msg = hello();
    msg.unix_fds = Some(0);
    let bytes = msg.to_bytes().unwrap();
    let back = Message::parse(&bytes).unwrap();
    assert_eq!(back.unix_fds, Some(0));
}

#[test]
fn message_rejects_a_body_without_a_signature() {
    let mut msg = hello();
    msg.body = vec![DValue::str("x")];
    assert!(msg.to_bytes().is_err());
}

#[test]
fn message_type_codes_match_the_specification() {
    assert_eq!(MessageType::MethodCall.code(), 1);
    assert_eq!(MessageType::MethodReturn.code(), 2);
    assert_eq!(MessageType::Error.code(), 3);
    assert_eq!(MessageType::Signal.code(), 4);
    assert!(MessageType::from_code(0).is_err());
    assert!(MessageType::from_code(5).is_err());
}

// -------------------------------------------------------- bus addresses

#[test]
fn address_parses_a_path() {
    let a = parse_address("unix:path=/run/dbus/system_bus_socket").unwrap();
    assert_eq!(a, vec![BusAddress::Path("/run/dbus/system_bus_socket".to_owned())]);
}

#[test]
fn address_parses_an_abstract_socket_with_a_guid() {
    let a = parse_address("unix:abstract=/tmp/dbus-Ab12,guid=deadbeef").unwrap();
    assert_eq!(a, vec![BusAddress::Abstract("/tmp/dbus-Ab12".to_owned())]);
}

#[test]
fn address_decodes_percent_escapes() {
    let a = parse_address("unix:path=/tmp/a%20b").unwrap();
    assert_eq!(a, vec![BusAddress::Path("/tmp/a b".to_owned())]);
}

#[test]
fn address_skips_transports_we_cannot_use() {
    let a = parse_address("tcp:host=localhost,port=1;unix:path=/run/x").unwrap();
    assert_eq!(a, vec![BusAddress::Path("/run/x".to_owned())]);
}

#[test]
fn address_rejects_useless_input() {
    assert!(parse_address("").is_err());
    assert!(parse_address("tcp:host=localhost,port=1").is_err());
    assert!(parse_address("unix:guid=abc").is_err());
    assert!(parse_address("nonsense").is_err());
    assert!(parse_address("unix:path=/a,abstract=/b").is_err());
}

#[test]
fn hex_encoding_matches_what_sasl_external_expects() {
    // The uid is hex-encoded *as ASCII decimal*: 0 -> "0" -> "30".
    assert_eq!(hex_encode(b"0"), "30");
    assert_eq!(hex_encode(b"1000"), "31303030");
}

// ------------------------------------------------------- unit name validation

#[test]
fn valid_unit_names_are_accepted() {
    let good = [
        "nginx.service",
        "sshd.service",
        "getty@tty1.service",
        "user@1000.service",
        "dbus-org.freedesktop.resolve1.service",
        "systemd-journald.socket",
        "dev-sda1.device",
        "run-user-1000.mount",
        "apt-daily.timer",
        "machine.slice",
        "session-3.scope",
        "a.service",
        "my_app-1.2.3.service",
        "docker.service",
        r"systemd-fsck@dev-disk-by\x2duuid.service",
        "postgresql@14-main.service",
    ];
    for name in good {
        assert!(validate_unit_name(name).is_ok(), "{name} should be valid");
    }
}

#[test]
fn unit_name_rejects_shell_metacharacters() {
    // The headline injection attempt. There is no shell, but a name that
    // reaches argv unvalidated is still not something we want to normalise.
    let e = validate_unit_name("nginx.service; rm -rf /").unwrap_err();
    assert_eq!(e.http_status(), 400);
    assert!(validate_unit_name("nginx.service && reboot").is_err());
    assert!(validate_unit_name("nginx.service|tee").is_err());
    assert!(validate_unit_name("$(reboot).service").is_err());
    assert!(validate_unit_name("`reboot`.service").is_err());
}

#[test]
fn unit_name_rejects_path_traversal() {
    assert!(validate_unit_name("../../etc/passwd").is_err());
    assert!(validate_unit_name("/etc/systemd/system/evil.service").is_err());
    assert!(validate_unit_name("../evil.service").is_err());
    assert!(validate_unit_name("a/b.service").is_err());
}

#[test]
fn unit_name_rejects_control_characters() {
    assert!(validate_unit_name("a\nb.service").is_err());
    assert!(validate_unit_name("a\rb.service").is_err());
    assert!(validate_unit_name("a\tb.service").is_err());
    assert!(validate_unit_name("a\0b.service").is_err());
    assert!(validate_unit_name("a b.service").is_err());
}

#[test]
fn unit_name_rejects_a_leading_dash_because_systemctl_would_read_it_as_an_option() {
    let e = validate_unit_name("-h.service").unwrap_err();
    assert!(format!("{e}").contains("begin with `-`"), "got: {e}");
    assert!(validate_unit_name("--version.service").is_err());
    // A dash elsewhere is perfectly normal.
    assert!(validate_unit_name("network-online.service").is_ok());
}

#[test]
fn unit_name_rejects_bad_lengths() {
    assert!(validate_unit_name("").is_err());
    let long = format!("{}.service", "a".repeat(300));
    assert!(validate_unit_name(&long).is_err());
    // 255 exactly is the boundary and must be accepted.
    let exact = format!("{}.service", "a".repeat(255 - ".service".len()));
    assert_eq!(exact.len(), 255);
    assert!(validate_unit_name(&exact).is_ok());
    let one_over = format!("{}.service", "a".repeat(256 - ".service".len()));
    assert!(validate_unit_name(&one_over).is_err());
}

#[test]
fn unit_name_requires_a_known_suffix() {
    assert!(validate_unit_name("nginx").is_err());
    assert!(validate_unit_name("nginx.servic").is_err());
    assert!(validate_unit_name("nginx.services").is_err());
    assert!(validate_unit_name("nginx.SERVICE").is_err());
    assert!(validate_unit_name("nginx.conf").is_err());
}

#[test]
fn unit_name_requires_a_stem() {
    assert!(validate_unit_name(".service").is_err());
    assert!(validate_unit_name("..service").is_err());
    assert!(validate_unit_name("...service").is_err());
}

#[test]
fn unit_name_rejects_non_ascii() {
    assert!(validate_unit_name("nginx\u{00e9}.service").is_err());
    assert!(validate_unit_name("\u{1f600}.service").is_err());
}

#[test]
fn unit_name_errors_are_human_readable() {
    let e = validate_unit_name("nginx.service; rm -rf /").unwrap_err();
    let msg = e.user_message();
    assert!(msg.contains("not a valid service name"), "got: {msg}");
    assert!(!msg.contains("EINVAL"));
    assert!(e.technical_detail().contains("invalid unit name"));
}

#[test]
fn unit_suffix_and_display_name() {
    assert_eq!(unit_suffix("nginx.service"), Some(".service"));
    assert_eq!(unit_suffix("apt-daily.timer"), Some(".timer"));
    assert_eq!(unit_suffix("nginx"), None);
    assert_eq!(display_name("nginx.service"), "nginx");
    assert_eq!(display_name("getty@tty1.service"), "getty@tty1");
    assert_eq!(display_name("plain"), "plain");
}

// ---------------------------------------------------------------- filtering

#[test]
fn interesting_services_are_kept() {
    for name in [
        "nginx.service",
        "sshd.service",
        "docker.service",
        "postgresql.service",
        "systemd-resolved.service",
        "systemd-journald.service",
        "my-app.service",
    ] {
        assert!(is_interesting_service(name), "{name} should be listed");
    }
}

#[test]
fn non_service_unit_types_are_excluded() {
    for name in [
        "init.scope",
        "user.slice",
        "boot.mount",
        "dev-sda1.device",
        "multi-user.target",
        "sshd.socket",
        "apt-daily.timer",
        "systemd-ask-password-wall.path",
        "dev-sda2.swap",
        "proc-sys-fs-binfmt_misc.automount",
    ] {
        assert!(!is_interesting_service(name), "{name} should be filtered out");
    }
}

#[test]
fn systemd_template_noise_is_excluded() {
    for name in [
        "getty@.service",
        "systemd-fsck@dev-sda1.service",
        r"systemd-backlight@backlight:acpi_video0.service",
        "user@1000.service",
        "user-runtime-dir@1000.service",
        "session-7.service",
    ] {
        assert!(!is_interesting_service(name), "{name} should be filtered out");
    }
}

#[test]
fn filtering_rejects_junk() {
    assert!(!is_interesting_service(""));
    assert!(!is_interesting_service("nginx"));
    assert!(!is_interesting_service("/etc/x.service"));
    assert!(!is_interesting_service(".service"));
}

// -------------------------------------------------------------- state rollup

#[test]
fn state_rollup_table() {
    let cases: &[(&str, &str, &str)] = &[
        ("active", "running", "running"),
        ("active", "exited", "running"),
        ("active", "listening", "running"),
        ("activating", "start-pre", "starting"),
        ("activating", "auto-restart", "starting"),
        ("reloading", "reload", "starting"),
        ("deactivating", "stop-sigterm", "stopping"),
        ("inactive", "dead", "stopped"),
        ("failed", "failed", "failed"),
        ("", "", "unknown"),
        ("maintenance", "maintenance", "unknown"),
    ];
    for (active, sub, want) in cases {
        assert_eq!(rollup_state(active, sub), *want, "({active}, {sub})");
    }
}

// -------------------------------------------------------------------- units

fn sample_list_entry() -> DValue {
    DValue::Struct(vec![
        DValue::str("nginx.service"),
        DValue::str("A high performance web server"),
        DValue::str("loaded"),
        DValue::str("active"),
        DValue::str("running"),
        DValue::str(""),
        DValue::ObjectPath("/org/freedesktop/systemd1/unit/nginx_2eservice".to_owned()),
        DValue::Uint32(0),
        DValue::str(""),
        DValue::ObjectPath("/".to_owned()),
    ])
}

#[test]
fn unit_decodes_a_list_units_entry() {
    let u = Unit::from_list_entry(&sample_list_entry()).unwrap();
    assert_eq!(u.name, "nginx.service");
    assert_eq!(u.load_state, "loaded");
    assert_eq!(u.sub_state, "running");
    assert_eq!(u.object_path, "/org/freedesktop/systemd1/unit/nginx_2eservice");
    assert_eq!(u.state(), "running");
    assert_eq!(u.display_name(), "nginx");
}

#[test]
fn unit_rejects_a_malformed_list_units_entry() {
    assert!(Unit::from_list_entry(&DValue::str("nope")).is_err());
    assert!(Unit::from_list_entry(&DValue::Struct(vec![DValue::str("a")])).is_err());
}

#[test]
fn unit_json_has_the_documented_shape() {
    let mut u = Unit::from_list_entry(&sample_list_entry()).unwrap();
    u.enabled = Some("enabled".to_owned());
    let j = u.to_json();
    assert_eq!(j.get("name").and_then(|v| v.as_str()), Some("nginx.service"));
    assert_eq!(j.get("display_name").and_then(|v| v.as_str()), Some("nginx"));
    assert_eq!(
        j.get("description").and_then(|v| v.as_str()),
        Some("A high performance web server")
    );
    assert_eq!(j.get("load_state").and_then(|v| v.as_str()), Some("loaded"));
    assert_eq!(j.get("active_state").and_then(|v| v.as_str()), Some("active"));
    assert_eq!(j.get("sub_state").and_then(|v| v.as_str()), Some("running"));
    assert_eq!(j.get("state").and_then(|v| v.as_str()), Some("running"));
    assert_eq!(j.get("enabled").and_then(|v| v.as_str()), Some("enabled"));
    assert_eq!(j.get("can_start").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(j.get("can_stop").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(j.get("can_restart").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn unit_json_reports_a_masked_unit_as_not_actionable() {
    let mut u = Unit::from_list_entry(&sample_list_entry()).unwrap();
    u.load_state = "masked".to_owned();
    let j = u.to_json();
    assert_eq!(j.get("can_start").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(j.get("can_restart").and_then(|v| v.as_bool()), Some(false));
}

#[test]
fn unit_json_uses_null_for_unknown_enablement() {
    let u = Unit::from_list_entry(&sample_list_entry()).unwrap();
    assert!(u.to_json().get("enabled").unwrap().is_null());
}

#[test]
fn units_json_is_an_array() {
    let u = Unit::from_list_entry(&sample_list_entry()).unwrap();
    let v = units_json(&[u]);
    assert_eq!(v.as_array().map(<[_]>::len), Some(1));
}

fn dict(pairs: Vec<(&str, DValue)>) -> DValue {
    DValue::Array(
        pairs
            .into_iter()
            .map(|(k, v)| DValue::DictEntry(Box::new(DValue::str(k)), Box::new(DValue::variant(v))))
            .collect(),
    )
}

#[test]
fn unit_detail_decodes_property_bags() {
    let unit = dict(vec![
        ("Id", DValue::str("nginx.service")),
        ("Description", DValue::str("A high performance web server")),
        ("LoadState", DValue::str("loaded")),
        ("ActiveState", DValue::str("active")),
        ("SubState", DValue::str("running")),
        ("FragmentPath", DValue::str("/lib/systemd/system/nginx.service")),
        ("UnitFileState", DValue::str("enabled")),
        // 2023-11-14T22:13:20Z in microseconds.
        ("ActiveEnterTimestamp", DValue::Uint64(1_700_000_000_000_000)),
        (
            "Documentation",
            DValue::Array(vec![DValue::str("man:nginx(8)")]),
        ),
        ("Requires", DValue::Array(vec![DValue::str("system.slice")])),
        ("Wants", DValue::Array(vec![DValue::str("network.target")])),
        ("TriggeredBy", DValue::Array(vec![])),
        ("CanStart", DValue::Bool(true)),
        ("CanStop", DValue::Bool(true)),
        ("CanReload", DValue::Bool(true)),
    ]);
    let service = dict(vec![
        ("MainPID", DValue::Uint32(1234)),
        ("MemoryCurrent", DValue::Uint64(12_582_912)),
        ("CPUUsageNSec", DValue::Uint64(4_200_000_000)),
        ("TasksCurrent", DValue::Uint64(5)),
        ("TasksMax", DValue::Uint64(4915)),
        ("NRestarts", DValue::Uint32(0)),
        ("Result", DValue::str("success")),
        ("ExecMainStatus", DValue::Int32(0)),
    ]);

    let d = UnitDetail::from_properties("nginx.service", &unit, &service);
    assert_eq!(d.unit.name, "nginx.service");
    assert_eq!(d.state(), "running");
    assert_eq!(d.main_pid, Some(1234));
    assert_eq!(d.memory_bytes, Some(12_582_912));
    assert_eq!(d.cpu_usage_nsec, Some(4_200_000_000));
    assert_eq!(d.tasks_current, Some(5));
    assert_eq!(d.tasks_max, Some(4915));
    assert_eq!(d.restart_count, Some(0));
    assert_eq!(d.active_since, Some(1_700_000_000), "microseconds -> seconds");
    assert_eq!(d.fragment_path.as_deref(), Some("/lib/systemd/system/nginx.service"));
    assert_eq!(d.unit_file_state.as_deref(), Some("enabled"));
    assert_eq!(d.result.as_deref(), Some("success"));
    assert_eq!(d.exec_main_status, Some(0));
    assert_eq!(d.documentation, vec!["man:nginx(8)".to_owned()]);
    assert_eq!(d.requires, vec!["system.slice".to_owned()]);
    assert_eq!(d.wants, vec!["network.target".to_owned()]);
    assert!(d.triggered_by.is_empty());
}

#[test]
fn unit_detail_maps_sentinels_to_null() {
    let unit = dict(vec![
        ("Id", DValue::str("stopped.service")),
        ("LoadState", DValue::str("loaded")),
        ("ActiveState", DValue::str("inactive")),
        ("SubState", DValue::str("dead")),
        ("FragmentPath", DValue::str("")),
        ("UnitFileState", DValue::str("")),
        ("ActiveEnterTimestamp", DValue::Uint64(0)),
    ]);
    let service = dict(vec![
        ("MainPID", DValue::Uint32(0)),
        ("MemoryCurrent", DValue::Uint64(u64::MAX)),
        ("CPUUsageNSec", DValue::Uint64(u64::MAX)),
        ("TasksCurrent", DValue::Uint64(u64::MAX)),
        ("TasksMax", DValue::Uint64(u64::MAX)),
        ("Result", DValue::str("")),
    ]);
    let d = UnitDetail::from_properties("stopped.service", &unit, &service);
    assert_eq!(d.state(), "stopped");
    assert_eq!(d.main_pid, None);
    assert_eq!(d.memory_bytes, None);
    assert_eq!(d.cpu_usage_nsec, None);
    assert_eq!(d.tasks_current, None);
    assert_eq!(d.tasks_max, None);
    assert_eq!(d.active_since, None);
    assert_eq!(d.fragment_path, None);
    assert_eq!(d.unit_file_state, None);
    assert_eq!(d.result, None);

    let j = d.to_json();
    for key in [
        "main_pid",
        "memory_bytes",
        "cpu_usage_nsec",
        "tasks_current",
        "tasks_max",
        "active_since",
        "fragment_path",
        "unit_file_state",
        "result",
    ] {
        assert!(j.get(key).unwrap().is_null(), "{key} should be null");
    }
}

#[test]
fn unit_detail_survives_entirely_empty_property_bags() {
    let d = UnitDetail::from_properties(
        "ghost.service",
        &DValue::Array(vec![]),
        &DValue::Array(vec![]),
    );
    assert_eq!(d.unit.name, "ghost.service");
    assert_eq!(d.state(), "unknown");
    assert!(d.to_json().get("documentation").unwrap().as_array().unwrap().is_empty());
}

#[test]
fn unit_detail_json_adds_the_deep_fields() {
    let unit = dict(vec![
        ("Id", DValue::str("nginx.service")),
        ("LoadState", DValue::str("loaded")),
        ("ActiveState", DValue::str("active")),
        ("SubState", DValue::str("running")),
        ("CanReload", DValue::Bool(true)),
    ]);
    let service = dict(vec![
        ("MainPID", DValue::Uint32(99)),
        ("NRestarts", DValue::Uint32(17)),
    ]);
    let j = UnitDetail::from_properties("nginx.service", &unit, &service).to_json();
    assert_eq!(j.get("state").and_then(|v| v.as_str()), Some("running"));
    assert_eq!(j.get("main_pid").and_then(|v| v.as_u64()), Some(99));
    assert_eq!(
        j.get("restart_count").and_then(|v| v.as_u64()),
        Some(17),
        "a restart count is a fact, not a sentinel"
    );
    assert_eq!(j.get("can_reload").and_then(|v| v.as_bool()), Some(true));
    // The base fields are still present.
    assert_eq!(j.get("display_name").and_then(|v| v.as_str()), Some("nginx"));
}

#[test]
fn dict_get_unwraps_variants_and_misses_cleanly() {
    let d = dict(vec![("A", DValue::Uint32(1))]);
    assert_eq!(d.dict_get("A").and_then(DValue::as_u32), Some(1));
    assert!(d.dict_get("B").is_none());
    assert!(DValue::str("not a dict").dict_get("A").is_none());
}

// ------------------------------------------------------ systemctl parsing

#[test]
fn parses_the_tabular_list_units_form() {
    let out = "\
nginx.service          loaded active   running A high performance web server
ssh.service            loaded active   running OpenBSD Secure Shell server
snapd.service          loaded inactive dead    Snap Daemon
dead.service           not-found inactive dead dead.service
";
    let units = parse_list_units_table(out);
    assert_eq!(units.len(), 4);
    assert_eq!(units[0].name, "nginx.service");
    assert_eq!(units[0].active_state, "active");
    assert_eq!(units[0].description, "A high performance web server");
    assert_eq!(units[2].state(), "stopped");
    assert_eq!(units[3].load_state, "not-found");
}

#[test]
fn tabular_parsing_tolerates_a_status_glyph_and_a_header() {
    let out = "\
UNIT LOAD ACTIVE SUB DESCRIPTION
\u{25cf} broken.service loaded failed failed Some Broken Thing
";
    let units = parse_list_units_table(out);
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].name, "broken.service");
    assert_eq!(units[0].state(), "failed");
}

#[test]
fn tabular_parsing_skips_junk_lines() {
    let units = parse_list_units_table("\n   \nnot-a-unit row here now\n");
    assert!(units.is_empty(), "a name with no dot is not a unit");
}

#[test]
fn parses_key_value_output_including_values_containing_equals() {
    let m = parse_key_values("Id=nginx.service\nEnvironment=A=1 B=2\nEmpty=\n");
    assert_eq!(m.get("Id").map(String::as_str), Some("nginx.service"));
    assert_eq!(m.get("Environment").map(String::as_str), Some("A=1 B=2"));
    assert_eq!(m.get("Empty").map(String::as_str), Some(""));
}

#[test]
fn unit_detail_from_systemctl_show_matches_the_dbus_shape() {
    let mut p = BTreeMap::new();
    for (k, v) in [
        ("Id", "nginx.service"),
        ("Description", "A high performance web server"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("FragmentPath", "/lib/systemd/system/nginx.service"),
        ("UnitFileState", "enabled"),
        ("ActiveEnterTimestamp", "@1700000000"),
        ("Documentation", "man:nginx(8) https://nginx.org/en/docs/"),
        ("Requires", "system.slice sysinit.target"),
        ("Wants", "network.target"),
        ("TriggeredBy", ""),
        ("CanStart", "yes"),
        ("CanStop", "yes"),
        ("CanReload", "yes"),
        ("MainPID", "1234"),
        ("MemoryCurrent", "12582912"),
        ("CPUUsageNSec", "4200000000"),
        ("TasksCurrent", "5"),
        ("TasksMax", "4915"),
        ("NRestarts", "3"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        p.insert(k.to_owned(), v.to_owned());
    }
    let d = UnitDetail::from_show_properties("nginx.service", &p);
    assert_eq!(d.state(), "running");
    assert_eq!(d.main_pid, Some(1234));
    assert_eq!(d.memory_bytes, Some(12_582_912));
    assert_eq!(d.tasks_max, Some(4915));
    assert_eq!(d.restart_count, Some(3));
    assert_eq!(d.active_since, Some(1_700_000_000));
    assert_eq!(d.documentation.len(), 2);
    assert_eq!(d.requires.len(), 2);
    assert!(d.triggered_by.is_empty());
    assert_eq!(d.can_reload, Some(true));
    assert_eq!(d.unit.enabled.as_deref(), Some("enabled"));
}

#[test]
fn unit_detail_from_systemctl_show_handles_textual_sentinels() {
    let mut p = BTreeMap::new();
    for (k, v) in [
        ("Id", "idle.service"),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("MemoryCurrent", "[not set]"),
        ("TasksMax", "infinity"),
        ("CPUUsageNSec", "18446744073709551615"),
        // Without `--timestamp=unix` this is a formatted date we refuse to parse.
        ("ActiveEnterTimestamp", "Thu 2023-11-14 22:13:20 UTC"),
        ("FragmentPath", ""),
        ("UnitFileState", ""),
    ] {
        p.insert(k.to_owned(), v.to_owned());
    }
    let d = UnitDetail::from_show_properties("idle.service", &p);
    assert_eq!(d.main_pid, None);
    assert_eq!(d.memory_bytes, None);
    assert_eq!(d.tasks_max, None);
    assert_eq!(d.cpu_usage_nsec, None);
    assert_eq!(d.active_since, None);
    assert_eq!(d.fragment_path, None);
    assert_eq!(d.unit_file_state, None);
    assert_eq!(d.state(), "stopped");
}

// --------------------------------------------------------------- errors

#[test]
fn dbus_errors_classify_reachability() {
    use std::io::{Error, ErrorKind};
    assert!(DBusError::Io(Error::from(ErrorKind::ConnectionRefused)).is_unreachable());
    assert!(DBusError::Address("x".into()).is_unreachable());
    assert!(DBusError::Auth("x".into()).is_unreachable());
    assert!(DBusError::Timeout.is_unreachable());
    assert!(
        !DBusError::Remote { name: "a.B".into(), message: "no".into() }.is_unreachable(),
        "a remote refusal means the bus works"
    );
}

#[test]
fn remote_errors_become_product_errors() {
    use crate::error::SystemdError;
    let no_unit = SystemdError::from_dbus(
        "nope.service",
        DBusError::Remote {
            name: "org.freedesktop.systemd1.NoSuchUnit".into(),
            message: "Unit nope.service not found.".into(),
        },
    );
    assert!(matches!(no_unit, SystemdError::NoSuchUnit(_)));
    assert_eq!(no_unit.http_status(), 404);
    assert!(no_unit.user_message().contains("no service called"));

    let denied = SystemdError::from_dbus(
        "nginx.service",
        DBusError::Remote {
            name: "org.freedesktop.DBus.Error.AccessDenied".into(),
            message: "".into(),
        },
    );
    assert!(matches!(denied, SystemdError::PermissionDenied(_)));
    assert_eq!(denied.http_status(), 403);

    let gone = SystemdError::from_dbus(
        "nginx.service",
        DBusError::Remote {
            name: "org.freedesktop.DBus.Error.ServiceUnknown".into(),
            message: "".into(),
        },
    );
    assert_eq!(gone.http_status(), 503);
}

#[test]
fn user_messages_never_leak_error_codes() {
    use crate::error::SystemdError;
    use std::io::{Error, ErrorKind};
    let e = SystemdError::Dbus(DBusError::Io(Error::from(ErrorKind::ConnectionRefused)));
    let msg = e.user_message();
    assert!(msg.contains("couldn't reach"), "got: {msg}");
    for leak in ["ECONNREFUSED", "ENOENT", "EACCES", "os error"] {
        assert!(!msg.contains(leak), "user message leaked {leak}: {msg}");
    }
    // The detail is still available for an engineer.
    assert!(!e.technical_detail().is_empty());
}

// -------------------------------------------------------------- detection

#[test]
fn detect_reports_unavailable_without_systemd() {
    use crate::error::SystemdError;
    use crate::systemd::{detect, is_systemd_running};
    if is_systemd_running() {
        // On a real systemd host this test has nothing to assert about the
        // negative path; the live tests cover the positive one.
        return;
    }
    let Err(e) = detect() else { panic!("there is no systemd here") };
    assert!(matches!(e, SystemdError::Unavailable(_)));
    assert!(e.user_message().contains("systemd"), "got: {}", e.user_message());
    assert_eq!(e.http_status(), 503);
}
