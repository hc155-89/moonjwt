///|
/// A verified compact JWT: the parsed header plus the trusted claims.
pub struct DecodedJwt {
  header : Header
  payload : Payload
}

///|
/// The header of a verified token.
pub fn DecodedJwt::header(self : DecodedJwt) -> Header {
  self.header
}

///|
/// The claims of a verified token.
pub fn DecodedJwt::payload(self : DecodedJwt) -> Payload {
  self.payload
}

///|
/// Parses one base64url segment as JSON, translating parser errors into the
/// public `JwtError` type.
fn parse_json_segment(segment : StringView) -> Json raise JwtError {
  @json.parse(segment) catch {
    _ => raise InvalidJson("JWT segment is not valid JSON")
  }
}

///|
/// Compares two byte strings without short-circuiting on the first mismatch.
///
/// Signature comparison must not leak where the first differing byte is
/// (RFC 8725 §2.6). The length check itself is unavoidable and reveals only
/// the public signature length.
fn constant_time_equal(left : BytesView, right : BytesView) -> Bool {
  if left.length() != right.length() {
    return false
  }
  let mut difference = 0
  for i in 0..<left.length() {
    difference = difference | (left[i].to_int() ^ right[i].to_int())
  }
  difference == 0
}

///|
/// Signs a payload with HS256 using a UTF-8 secret.
pub fn encode(payload : Payload, secret : StringView) -> String raise JwtError {
  encode_with_key(payload, @utf8.encode(secret))
}

///|
/// Signs a payload with HS256 using raw key bytes.
///
/// This is the entry point for JWK `oct` keys, whose bytes are base64url
/// decoded rather than interpreted as text.
pub fn encode_with_key(
  payload : Payload,
  secret : BytesView,
) -> String raise JwtError {
  encode_with_header(payload, Header::new(HS256), secret)
}

///|
/// Signs a payload with HS256 and an explicit header.
///
/// Use this overload to attach a `kid` so that a verifier with a JWKS can
/// select the right key.
pub fn encode_with_header(
  payload : Payload,
  header : Header,
  secret : BytesView,
) -> String raise JwtError {
  match header.algorithm() {
    HS256 => ()
    RS256 => raise UnsupportedAlgorithm("RS256")
  }
  let header_segment = encode_base64url_text(header.to_json().stringify())
  let payload_segment = encode_base64url_text(payload.to_json().stringify())
  let signing_input = header_segment + "." + payload_segment
  let signature = hmac_sha256(secret, @utf8.encode(signing_input))
  signing_input + "." + encode_base64url(signature)
}

///|
/// Verifies and decodes a compact JWT with an HS256 UTF-8 secret.
pub fn decode(
  token : StringView,
  secret : StringView,
) -> DecodedJwt raise JwtError {
  decode_with_key(token, @utf8.encode(secret))
}

///|
/// Verifies and decodes a compact JWT with raw HS256 key bytes.
///
/// The signature is checked before the payload is parsed, so untrusted claims
/// are never surfaced from a token whose signature failed.
pub fn decode_with_key(
  token : StringView,
  secret : BytesView,
) -> DecodedJwt raise JwtError {
  let segments = Array::from_iter(token.split("."))
  guard segments.length() == 3 else {
    raise InvalidToken("a compact JWT must contain exactly three segments")
  }
  let header_text = decode_base64url_text(segments[0])
  let header = Header::from_json(parse_json_segment(header_text))
  match header.algorithm() {
    HS256 => ()
    RS256 => raise UnsupportedAlgorithm("RS256")
  }
  let signing_input = segments[0].to_owned() + "." + segments[1].to_owned()
  let expected = hmac_sha256(secret, @utf8.encode(signing_input))
  let actual = decode_base64url(segments[2])
  if !constant_time_equal(expected, actual) {
    raise InvalidSignature
  }
  let payload_text = decode_base64url_text(segments[1])
  let payload = Payload::from_json(parse_json_segment(payload_text))
  { header, payload, }
}
