///|
/// Provider metadata from an OpenID Connect Discovery document (OIDC Discovery
/// 1.0 §3).
///
/// Only the members moonjwt actually uses are surfaced. Unknown members are
/// ignored, which keeps the parser tolerant of the many extensions providers
/// add without trusting them for a security decision.
pub struct ProviderMetadata {
  issuer : String
  authorization_endpoint : String
  token_endpoint : String
  jwks_uri : String
  userinfo_endpoint : String?
  scopes_supported : Array[String]
  response_types_supported : Array[String]
  id_token_signing_alg_values_supported : Array[String]
}

///|
fn required_string(
  object : Map[String, Json],
  name : String,
) -> String raise OidcError {
  match object.get(name) {
    Some(String(value)) => {
      if value.trim().length() == 0 {
        raise InvalidResponse(name + " must not be empty")
      }
      value
    }
    Some(_) => raise InvalidResponse(name + " must be a string")
    None => raise InvalidResponse("discovery document is missing " + name)
  }
}

///|
fn optional_string(
  object : Map[String, Json],
  name : String,
) -> String? raise OidcError {
  match object.get(name) {
    Some(String(value)) => Some(value)
    Some(_) => raise InvalidResponse(name + " must be a string")
    None => None
  }
}

///|
fn string_array(
  object : Map[String, Json],
  name : String,
) -> Array[String] raise OidcError {
  match object.get(name) {
    Some(Array(items)) => {
      let values : Array[String] = []
      for item in items {
        match item {
          String(value) => values.push(value)
          _ => raise InvalidResponse(name + " must contain only strings")
        }
      }
      values
    }
    Some(_) => raise InvalidResponse(name + " must be an array")
    None => []
  }
}

///|
/// Parses an OpenID Connect Discovery document.
///
/// `issuer`, `authorization_endpoint`, `token_endpoint` and `jwks_uri` are
/// required: without them neither the code flow nor ID token verification can
/// be completed, so a partial document is rejected instead of half-used.
pub fn ProviderMetadata::from_json(
  json : Json,
) -> ProviderMetadata raise OidcError {
  let object = match json {
    Object(object) => object
    _ => raise InvalidResponse("discovery document must be a JSON object")
  }
  let metadata : ProviderMetadata = {
    issuer: required_string(object, "issuer"),
    authorization_endpoint: required_string(object, "authorization_endpoint"),
    token_endpoint: required_string(object, "token_endpoint"),
    jwks_uri: required_string(object, "jwks_uri"),
    userinfo_endpoint: optional_string(object, "userinfo_endpoint"),
    scopes_supported: string_array(object, "scopes_supported"),
    response_types_supported: string_array(object, "response_types_supported"),
    id_token_signing_alg_values_supported: string_array(
      object, "id_token_signing_alg_values_supported",
    ),
  }
  metadata
}

///|
/// The issuer identifier, which must also be the `iss` claim of every ID token.
pub fn ProviderMetadata::issuer(self : ProviderMetadata) -> String {
  self.issuer
}

///|
/// The authorization endpoint used by the code flow.
pub fn ProviderMetadata::authorization_endpoint(
  self : ProviderMetadata,
) -> String {
  self.authorization_endpoint
}

///|
/// The token endpoint used for code exchange and refresh.
pub fn ProviderMetadata::token_endpoint(self : ProviderMetadata) -> String {
  self.token_endpoint
}

///|
/// The JWKS location used to verify ID token signatures.
pub fn ProviderMetadata::jwks_uri(self : ProviderMetadata) -> String {
  self.jwks_uri
}

///|
/// The optional userinfo endpoint.
pub fn ProviderMetadata::userinfo_endpoint(self : ProviderMetadata) -> String? {
  self.userinfo_endpoint
}

///|
/// Scopes the provider advertises.
pub fn ProviderMetadata::scopes_supported(
  self : ProviderMetadata,
) -> Array[String] {
  self.scopes_supported
}

///|
/// Response types the provider advertises.
pub fn ProviderMetadata::response_types_supported(
  self : ProviderMetadata,
) -> Array[String] {
  self.response_types_supported
}

///|
/// Signing algorithms the provider advertises for ID tokens.
pub fn ProviderMetadata::signing_algorithms(
  self : ProviderMetadata,
) -> Array[String] {
  self.id_token_signing_alg_values_supported
}

///|
/// Removes trailing slashes so a configured issuer cannot produce `//` in the
/// discovery URL.
fn strip_trailing_slashes(value : StringView) -> String {
  let characters : Array[Char] = []
  for character in value {
    characters.push(character)
  }
  while characters.length() > 0 && characters[characters.length() - 1] == '/' {
    ignore(characters.pop())
  }
  let builder = StringBuilder(size_hint=characters.length())
  for character in characters {
    builder.write_char(character)
  }
  builder.to_string()
}

///|
/// Builds the discovery URL for an issuer (OIDC Discovery 1.0 §4).
///
/// The well-known path is appended to the issuer, so the result is
/// `https://issuer/.well-known/openid-configuration` regardless of whether the
/// configured issuer carries a trailing slash.
pub fn ProviderMetadata::discovery_url(
  issuer : StringView,
) -> String raise OidcError {
  let trimmed = issuer.trim()
  if trimmed.length() == 0 {
    raise InvalidConfiguration("issuer must not be empty")
  }
  strip_trailing_slashes(trimmed) + discovery_path
}
