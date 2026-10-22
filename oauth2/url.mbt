///|
/// Uppercase hexadecimal digits, the only form RFC 3986 §2.1 permits in
/// percent-encoded octets.
const HEX_UPPER : Bytes = b"0123456789ABCDEF"

///|
/// RFC 3986 §2.3 unreserved characters never need encoding.
fn is_unreserved(code : Int32) -> Bool {
  match code {
    'A'..<='Z' | 'a'..<='z' | '0'..<='9' => true
    '-' | '.' | '_' | '~' => true
    _ => false
  }
}

///|
/// Encodes one query or form component.
///
/// `space_as_plus` selects the `application/x-www-form-urlencoded` spelling of
/// a space (RFC 6749 Appendix B) instead of the URI query spelling `%20`.
fn encode_component(value : StringView, space_as_plus : Bool) -> String {
  let bytes = @utf8.encode(value)
  let builder = StringBuilder(size_hint=bytes.length())
  for byte in bytes {
    let code = byte.to_int()
    if is_unreserved(code) {
      builder.write_char(byte.to_char())
    } else if space_as_plus && code == ' ' {
      builder.write_char('+')
    } else {
      builder.write_char('%')
      builder.write_char(HEX_UPPER[(code >> 4) & 0x0F].to_char())
      builder.write_char(HEX_UPPER[code & 0x0F].to_char())
    }
  }
  builder.to_string()
}

///|
/// Percent-encodes a UTF-8 string for use in a query component (RFC 3986
/// §2.1, §3.4). Spaces become `%20` rather than `+`, because `+` is only
/// special in `application/x-www-form-urlencoded`, not in a URI query.
fn percent_encode(value : StringView) -> String {
  encode_component(value, false)
}

///|
/// Encodes a UTF-8 string for an `application/x-www-form-urlencoded` body.
///
/// RFC 6749 Appendix B follows the HTML form rules, so a space becomes `+`.
fn form_encode(value : StringView) -> String {
  encode_component(value, true)
}
