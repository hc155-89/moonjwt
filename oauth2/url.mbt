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
/// Percent-encodes a UTF-8 string for use in a query component (RFC 3986
/// §2.1, §3.4). Spaces become `%20` rather than `+`, because `+` is only
/// special in `application/x-www-form-urlencoded`, not in a URI query.
fn percent_encode(value : StringView) -> String {
  let bytes = @utf8.encode(value)
  let builder = StringBuilder(size_hint=bytes.length())
  for byte in bytes {
    let code = byte.to_int()
    if is_unreserved(code) {
      builder.write_char(byte.to_char())
    } else {
      builder.write_char('%')
      builder.write_char(HEX_UPPER[(code >> 4) & 0x0F].to_char())
      builder.write_char(HEX_UPPER[code & 0x0F].to_char())
    }
  }
  builder.to_string()
}
