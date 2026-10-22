///|
/// Everything needed to validate an ID token (OIDC Core §3.1.3.7).
///
/// The current time is injected instead of read from the platform clock, which
/// keeps the check deterministic in tests and portable to WASI, where moonjwt
/// does not assume a clock is available.
pub struct IdTokenValidation {
  issuer : String
  audience : String
  nonce : String?
  now_seconds : Int64
  clock_skew_seconds : Int64
}

///|
/// Creates a validation policy for an issuer and client audience.
pub fn IdTokenValidation::new(
  issuer : StringView,
  audience : StringView,
  now_seconds : Int64,
) -> IdTokenValidation raise OidcError {
  if issuer.trim().length() == 0 {
    raise InvalidConfiguration("issuer must not be empty")
  }
  if audience.trim().length() == 0 {
    raise InvalidConfiguration("audience must not be empty")
  }
  {
    issuer: issuer.to_owned(),
    audience: audience.to_owned(),
    nonce: None,
    now_seconds,
    clock_skew_seconds: 0,
  }
}

///|
/// Requires the `nonce` claim to equal the value sent in the authorization
/// request.
///
/// Skipping this check lets a token minted for another session be replayed
/// against this one, which is exactly what the nonce exists to prevent.
pub fn IdTokenValidation::with_nonce(
  self : IdTokenValidation,
  nonce : StringView,
) -> IdTokenValidation raise OidcError {
  if nonce.trim().length() == 0 {
    raise InvalidConfiguration("nonce must not be empty")
  }
  { ..self, nonce: Some(nonce.to_owned()), }
}

///|
/// Allows a clock difference between the provider and this process.
pub fn IdTokenValidation::with_clock_skew(
  self : IdTokenValidation,
  seconds : Int64,
) -> IdTokenValidation raise OidcError {
  if seconds < 0 {
    raise InvalidConfiguration("clock skew must not be negative")
  }
  { ..self, clock_skew_seconds: seconds, }
}

///|
/// A verified ID token.
///
/// The value only exists after signature verification and every claim check,
/// so the claims can be trusted without further validation.
pub struct IdToken {
  subject : String
  payload : @core.Payload
}

///|
/// The `sub` claim, the provider's stable identifier for the user.
pub fn IdToken::subject(self : IdToken) -> String {
  self.subject
}

///|
/// All verified claims, for application specific values such as `email`.
pub fn IdToken::claims(self : IdToken) -> @core.Payload {
  self.payload
}

///|
/// Reads one verified claim.
pub fn IdToken::claim(self : IdToken, name : String) -> Json? {
  self.payload.get(name)
}

///|
/// Reads the `kid` from the token header so the matching JWKS key can be
/// selected before any signature work is done.
fn header_key_id(token : StringView) -> String? raise OidcError {
  let segments = Array::from_iter(token.split("."))
  if segments.length() != 3 {
    raise InvalidIdToken("an ID token must contain exactly three segments")
  }
  let text = @core.decode_base64url_text(segments[0]) catch {
    _ => raise InvalidIdToken("ID token header is not base64url encoded")
  }
  let header = @json.parse(text) catch {
    _ => raise InvalidIdToken("ID token header is not valid JSON")
  }
  match header {
    Object(object) =>
      match object.get("kid") {
        Some(String(kid)) => Some(kid)
        Some(_) => raise InvalidIdToken("\"kid\" must be a string")
        None => None
      }
    _ => raise InvalidIdToken("ID token header must be a JSON object")
  }
}

///|
/// Reads a NumericDate claim as whole seconds.
///
/// Fractional values are rejected rather than rounded, because `exp` is a
/// security boundary and rounding could extend a token's lifetime.
fn numeric_date(
  payload : @core.Payload,
  name : String,
) -> Int64 raise OidcError {
  match payload.get(name) {
    Some(Number(value, ..)) => {
      if value < 0.0 || value.floor() != value {
        raise InvalidIdToken(name + " must be a whole non-negative number")
      }
      value.to_int64()
    }
    Some(_) => raise InvalidIdToken(name + " must be a number")
    None => raise InvalidIdToken("ID token is missing \"" + name + "\"")
  }
}

///|
/// Checks `aud`, returning the number of audiences it lists.
fn audience_count(
  payload : @core.Payload,
  audience : String,
) -> Int32 raise OidcError {
  match payload.get("aud") {
    Some(String(value)) => {
      if value != audience {
        raise InvalidIdToken("ID token audience does not match this client")
      }
      1
    }
    Some(Array(items)) => {
      let mut found = false
      let mut count = 0
      for item in items {
        match item {
          String(value) => {
            if value == audience {
              found = true
            }
            count += 1
          }
          _ => raise InvalidIdToken("\"aud\" must contain only strings")
        }
      }
      if !found {
        raise InvalidIdToken("ID token audience does not match this client")
      }
      count
    }
    Some(_) => raise InvalidIdToken("\"aud\" must be a string or an array")
    None => raise InvalidIdToken("ID token is missing \"aud\"")
  }
}

///|
/// Verifies an ID token's signature against a JWKS and checks every claim in
/// the policy.
///
/// The signature is verified before any claim is read, so a forged token
/// cannot influence the checks. The key is selected by `kid`; a token without
/// `kid` is only accepted when the set contains exactly one usable RSA key.
pub fn validate_id_token(
  token : StringView,
  keys : Jwks,
  policy : IdTokenValidation,
) -> IdToken raise OidcError {
  let kid = header_key_id(token)
  let selected = match kid {
    Some(kid) => keys.key_by_id(kid)
    None => keys.only_key()
  }
  let key = match selected {
    Some(key) => key
    None => raise InvalidIdToken("no JWKS key matches this ID token")
  }
  let decoded = @core.decode_rs256_with_key(token, key.public_key()) catch {
    _ => raise InvalidIdToken("ID token signature verification failed")
  }
  let payload = decoded.payload()
  let issuer = match payload.get("iss") {
    Some(String(value)) => value
    Some(_) => raise InvalidIdToken("\"iss\" must be a string")
    None => raise InvalidIdToken("ID token is missing \"iss\"")
  }
  if issuer != policy.issuer {
    raise InvalidIdToken("ID token issuer does not match the expected issuer")
  }
  let audiences = audience_count(payload, policy.audience)
  if audiences > 1 {
    let authorized_party = match payload.get("azp") {
      Some(String(value)) => value
      Some(_) => raise InvalidIdToken("\"azp\" must be a string")
      None =>
        raise InvalidIdToken(
          "ID token with several audiences must carry \"azp\"",
        )
    }
    if authorized_party != policy.audience {
      raise InvalidIdToken("\"azp\" does not match this client")
    }
  }
  let expiration = numeric_date(payload, "exp")
  if expiration <= policy.now_seconds - policy.clock_skew_seconds {
    raise InvalidIdToken("ID token has expired")
  }
  let issued_at = numeric_date(payload, "iat")
  if issued_at > policy.now_seconds + policy.clock_skew_seconds {
    raise InvalidIdToken("ID token was issued in the future")
  }
  match payload.get("nbf") {
    Some(_) => {
      let not_before = numeric_date(payload, "nbf")
      if not_before > policy.now_seconds + policy.clock_skew_seconds {
        raise InvalidIdToken("ID token is not valid yet")
      }
    }
    None => ()
  }
  match policy.nonce {
    Some(expected) =>
      match payload.get("nonce") {
        Some(String(actual)) =>
          if actual != expected {
            raise InvalidIdToken("ID token nonce does not match the request")
          }
        Some(_) => raise InvalidIdToken("\"nonce\" must be a string")
        None => raise InvalidIdToken("ID token is missing \"nonce\"")
      }
    None => ()
  }
  let subject = match payload.get("sub") {
    Some(String(value)) => {
      if value.trim().length() == 0 {
        raise InvalidIdToken("\"sub\" must not be empty")
      }
      value
    }
    Some(_) => raise InvalidIdToken("\"sub\" must be a string")
    None => raise InvalidIdToken("ID token is missing \"sub\"")
  }
  { subject, payload, }
}
