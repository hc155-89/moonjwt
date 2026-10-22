///|
test "encode rfc 4648 vectors without padding" {
  assert_eq(encode_base64url(b""), "")
  assert_eq(encode_base64url(b"f"), "Zg")
  assert_eq(encode_base64url(b"fo"), "Zm8")
  assert_eq(encode_base64url(b"foo"), "Zm9v")
  assert_eq(encode_base64url(b"foob"), "Zm9vYg")
  assert_eq(encode_base64url(b"fooba"), "Zm9vYmE")
  assert_eq(encode_base64url(b"foobar"), "Zm9vYmFy")
}

///|
test "encode uses the url-safe alphabet" {
  // 0xFB 0xFF maps to the last two alphabet characters `-` and `_`.
  assert_eq(encode_base64url(Bytes::from_array([0xFB, 0xFF])), "-_8")
}

///|
test "decode rfc 4648 vectors" {
  assert_eq(decode_base64url(""), b"")
  assert_eq(decode_base64url("Zg"), b"f")
  assert_eq(decode_base64url("Zm8"), b"fo")
  assert_eq(decode_base64url("Zm9v"), b"foo")
  assert_eq(decode_base64url("Zm9vYg"), b"foob")
  assert_eq(decode_base64url("Zm9vYmE"), b"fooba")
  assert_eq(decode_base64url("Zm9vYmFy"), b"foobar")
}

///|
test "decode url-safe characters" {
  assert_eq(decode_base64url("-_8"), Bytes::from_array([0xFB, 0xFF]))
}

///|
test "text helpers round trip utf-8" {
  let text = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  assert_eq(encode_base64url_text(text), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
  assert_eq(decode_base64url_text("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), text)
  assert_eq(encode_base64url_text("中文"), "5Lit5paH")
  assert_eq(decode_base64url_text("5Lit5paH"), "中文")
}

///|
fn invalid_base64url(text : String) -> Bool {
  try {
    ignore(decode_base64url(text))
    false
  } catch {
    InvalidBase64Url(_) => true
    _ => false
  }
}

///|
test "decode rejects malformed input" {
  // Length 4n+1 can never be produced by a valid encoder.
  assert_true(invalid_base64url("A"))
  assert_true(invalid_base64url("Zm9vY"))
  // Padding and the standard alphabet are not base64url.
  assert_true(invalid_base64url("Zg=="))
  assert_true(invalid_base64url("Zm9v+"))
  assert_true(invalid_base64url("Zm9v/"))
  // Whitespace is never allowed inside a JWT segment.
  assert_true(invalid_base64url("Zm 9v"))
  // Non-zero trailing bits would make two encodings decode to the same bytes.
  assert_true(invalid_base64url("Zh"))
}
