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

///|
/// Signs a payload with RS256 using a PEM-encoded RSA private key.
pub fn encode_rs256(
  payload : Payload,
  private_key_pem : StringView,
) -> String raise JwtError {
  encode_rs256_with_header(payload, Header::new(RS256), private_key_pem)
}

///|
/// Signs a payload with RS256 and an explicit header.
///
/// The header must declare `RS256`; requesting `HS256` here is rejected rather
/// than silently switching algorithms (RFC 8725 §3.1).
pub fn encode_rs256_with_header(
  payload : Payload,
  header : Header,
  private_key_pem : StringView,
) -> String raise JwtError {
  match header.algorithm() {
    RS256 => ()
    HS256 => raise UnsupportedAlgorithm("HS256")
  }
  let key = RsaPrivateKey::from_pem(private_key_pem)
  let header_segment = encode_base64url_text(header.to_json().stringify())
  let payload_segment = encode_base64url_text(payload.to_json().stringify())
  let signing_input = header_segment + "." + payload_segment
  let signature = key.sign_sha256(@utf8.encode(signing_input))
  signing_input + "." + encode_base64url(signature)
}

///|
/// Verifies and decodes a compact JWT with an RS256 PEM public key.
///
/// The header must declare `RS256`: a token that claims `HS256` is rejected
/// before any key material is used, which prevents the classic RS256-to-HS256
/// confusion attack where the public key is reused as an HMAC secret.
pub fn decode_rs256(
  token : StringView,
  public_key_pem : StringView,
) -> DecodedJwt raise JwtError {
  decode_rs256_with_key(token, RsaPublicKey::from_pem(public_key_pem))
}

///|
/// Verifies and decodes a compact JWT with an already parsed RSA public key.
///
/// This is the entry point for keys that never existed as PEM, such as the JWK
/// members of an OIDC `jwks_uri` document. Algorithm checks and verification
/// order are identical to `decode_rs256`, so a JWKS cannot weaken the policy.
pub fn decode_rs256_with_key(
  token : StringView,
  key : RsaPublicKey,
) -> DecodedJwt raise JwtError {
  let segments = Array::from_iter(token.split("."))
  guard segments.length() == 3 else {
    raise InvalidToken("a compact JWT must contain exactly three segments")
  }
  let header_text = decode_base64url_text(segments[0])
  let header = Header::from_json(parse_json_segment(header_text))
  match header.algorithm() {
    RS256 => ()
    HS256 => raise UnsupportedAlgorithm("HS256")
  }
  let signing_input = segments[0].to_owned() + "." + segments[1].to_owned()
  let signature = decode_base64url(segments[2])
  if !key.verify_sha256(@utf8.encode(signing_input), signature) {
    raise InvalidSignature
  }
  let payload_text = decode_base64url_text(segments[1])
  let payload = Payload::from_json(parse_json_segment(payload_text))
  { header, payload, }
}
