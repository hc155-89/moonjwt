///|
/// PKCE code challenge transformations (RFC 7636 §4.2).
///
/// Only `S256` is offered. `plain` transmits the verifier itself in the
/// authorization request, so it protects nothing against a leaked request and
/// RFC 9700 §2.1.1 recommends `S256` for every client.
pub(all) enum PkceMethod {
  S256
}

///|
/// Returns the wire value of a PKCE transformation.
pub fn PkceMethod::value(self : PkceMethod) -> String {
  match self {
    S256 => "S256"
  }
}

///|
/// A code verifier together with its derived challenge.
pub struct Pkce {
  verifier : String
  challenge : String
  transformation : PkceMethod
}

///|
/// RFC 7636 §4.1: verifiers are 43 to 128 characters from the unreserved set.
fn validate_verifier(verifier : StringView) -> Unit raise OAuth2Error {
  let length = verifier.length()
  if length < 43 || length > 128 {
    raise InvalidRequest("PKCE code_verifier must be 43 to 128 characters")
  }
  for code_unit in verifier.code_units() {
    let code = code_unit.to_int()
    let allowed = match code {
      'A'..<='Z' | 'a'..<='z' | '0'..<='9' | '-' | '.' | '_' | '~' => true
      _ => false
    }
    if !allowed {
      raise InvalidRequest(
        "PKCE code_verifier may only contain unreserved characters",
      )
    }
  }
}

///|
/// Derives the `S256` challenge of a verifier: `BASE64URL(SHA256(verifier))`.
pub fn code_challenge_s256(verifier : StringView) -> String raise OAuth2Error {
  validate_verifier(verifier)
  @core.encode_base64url(@core.sha256(@utf8.encode(verifier)))
}

///|
/// Builds a PKCE pair from a caller-supplied code verifier.
///
/// The verifier is validated but not generated, which keeps entropy sourcing
/// in the caller's hands: a server or native host can use its own CSPRNG.
pub fn Pkce::from_verifier(verifier : StringView) -> Pkce raise OAuth2Error {
  validate_verifier(verifier)
  {
    verifier: verifier.to_owned(),
    challenge: code_challenge_s256(verifier),
    transformation: S256,
  }
}

///|
/// Builds a PKCE pair from raw entropy.
///
/// The entropy is base64url encoded, so 32 to 96 bytes map to a verifier
/// within the 43 to 128 character bounds. The caller must supply at least 32
/// bytes from a cryptographically secure source; this function cannot verify
/// the quality of the entropy.
pub fn Pkce::from_entropy(entropy : BytesView) -> Pkce raise OAuth2Error {
  let length = entropy.length()
  if length < 32 || length > 96 {
    raise InvalidRequest("PKCE entropy must be between 32 and 96 bytes")
  }
  Pkce::from_verifier(@core.encode_base64url(entropy))
}

///|
/// The verifier to send in the token request.
pub fn Pkce::verifier(self : Pkce) -> String {
  self.verifier
}

///|
/// The challenge to send in the authorization request.
pub fn Pkce::challenge(self : Pkce) -> String {
  self.challenge
}

///|
/// The transformation used to derive the challenge.
pub fn Pkce::transformation(self : Pkce) -> PkceMethod {
  self.transformation
}
