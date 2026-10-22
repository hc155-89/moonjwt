///|
/// RFC 4648 §5 base64url alphabet. It differs from the standard alphabet in
/// the last two characters (`-` and `_` instead of `+` and `/`) and never uses
/// padding, as required by RFC 7515 for JWS compact serialization.
const BASE64URL_ALPHABET : Bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

///|
/// Maps one ASCII code unit to its 6-bit value, or -1 when the character is
/// not part of the base64url alphabet.
fn base64url_value(code_unit : Int32) -> Int32 {
  match code_unit {
    'A'..<='Z' => code_unit - 'A'
    'a'..<='z' => code_unit - 'a' + 26
    '0'..<='9' => code_unit - '0' + 52
    '-' => 62
    '_' => 63
    _ => -1
  }
}

///|
/// Encodes bytes as unpadded base64url (RFC 4648 §5).
///
/// The output is always safe to embed in a JWT segment: it contains only
/// `A-Z`, `a-z`, `0-9`, `-` and `_`.
pub fn encode_base64url(bytes : BytesView) -> String {
  let full_groups = bytes.length() / 3
  let remainder = bytes.length() % 3
  let size_hint = full_groups * 4 +
    (if remainder == 0 { 0 } else { remainder + 1 })
  let builder = StringBuilder(size_hint~)
  for remaining = bytes {
    match remaining {
      [b0, b1, b2, .. rest] => {
        let n = (b0.to_int() << 16) | (b1.to_int() << 8) | b2.to_int()
        builder.write_char(BASE64URL_ALPHABET[(n >> 18) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[(n >> 12) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[(n >> 6) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[n & 0x3F].to_char())
        continue rest
      }
      [b0, b1] => {
        let n = (b0.to_int() << 16) | (b1.to_int() << 8)
        builder.write_char(BASE64URL_ALPHABET[(n >> 18) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[(n >> 12) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[(n >> 6) & 0x3F].to_char())
        break
      }
      [b0] => {
        let n = b0.to_int() << 16
        builder.write_char(BASE64URL_ALPHABET[(n >> 18) & 0x3F].to_char())
        builder.write_char(BASE64URL_ALPHABET[(n >> 12) & 0x3F].to_char())
        break
      }
      [] => break
    }
  }
  builder.to_string()
}

///|
/// Encodes a UTF-8 string as unpadded base64url. JWT headers and payloads are
/// JSON text, so this is the entry point used by the signing layer.
pub fn encode_base64url_text(text : StringView) -> String {
  encode_base64url(@utf8.encode(text))
}

///|
/// Decodes unpadded base64url into raw bytes.
///
/// Strictness is intentional: padding (`=`), the standard alphabet (`+`, `/`)
/// and non-zero trailing bits are rejected. A JWS parser that accepts those
/// variants would let multiple encodings map to the same token.
pub fn decode_base64url(text : StringView) -> Bytes raise JwtError {
  let length = text.length()
  if length % 4 == 1 {
    raise InvalidBase64Url("a base64url segment cannot have length 4n+1")
  }
  let buffer = @buffer.Buffer(size_hint=length / 4 * 3 + 3)
  let mut accumulator = 0
  let mut pending_bits = 0
  for code_unit in text.code_units() {
    let value = base64url_value(code_unit.to_int())
    if value < 0 {
      raise InvalidBase64Url("segment contains a non base64url character")
    }
    accumulator = (accumulator << 6) | value
    pending_bits += 6
    if pending_bits >= 8 {
      pending_bits -= 8
      buffer.write_byte(((accumulator >> pending_bits) & 0xFF).to_byte())
      accumulator = accumulator & ((1 << pending_bits) - 1)
    }
  }
  if pending_bits > 0 && accumulator != 0 {
    raise InvalidBase64Url("segment has non-zero trailing bits")
  }
  buffer.to_bytes()
}

///|
/// Decodes base64url that is expected to contain UTF-8 JSON text.
pub fn decode_base64url_text(text : StringView) -> String raise JwtError {
  let bytes = decode_base64url(text)
  @utf8.decode(bytes) catch {
    _ => raise InvalidBase64Url("segment is not valid UTF-8")
  }
}
