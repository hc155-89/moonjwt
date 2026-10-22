///|
/// A prepared token endpoint request.
///
/// The struct only carries data: moonjwt does not perform HTTP itself, so the
/// caller can send it with any client that supports method, headers and body.
pub struct TokenRequest {
  url : String
  http_method : String
  headers : Array[(String, String)]
  body : String
}

///|
/// The token endpoint URL.
pub fn TokenRequest::url(self : TokenRequest) -> String {
  self.url
}

///|
/// The HTTP method, always `"POST"`.
pub fn TokenRequest::http_method(self : TokenRequest) -> String {
  self.http_method
}

///|
/// The request headers.
pub fn TokenRequest::headers(self : TokenRequest) -> Array[(String, String)] {
  self.headers
}

///|
/// The form-urlencoded request body.
pub fn TokenRequest::body(self : TokenRequest) -> String {
  self.body
}

///|
/// Looks up a header by name.
pub fn TokenRequest::header(self : TokenRequest, name : String) -> String? {
  for header in self.headers {
    if header.0 == name {
      return Some(header.1)
    }
  }
  None
}

///|
fn require_parameter(
  name : String,
  value : StringView,
) -> Unit raise OAuth2Error {
  if value.trim().length() == 0 {
    raise InvalidRequest(name + " must not be empty")
  }
}

///|
fn encode_form(parameters : Array[(String, String)]) -> String {
  let builder = StringBuilder()
  let mut first = true
  for parameter in parameters {
    if !first {
      builder.write_char('&')
    }
    builder.write_string(form_encode(parameter.0))
    builder.write_char('=')
    builder.write_string(form_encode(parameter.1))
    first = false
  }
  builder.to_string()
}

///|
/// Adds client authentication and serializes the parameters.
///
/// Confidential clients authenticate with HTTP Basic (RFC 6749 §2.3.1), so
/// `client_id` is omitted from the body; RFC 6749 §4.1.3 only requires it when
/// the client does not authenticate. Public clients instead send `client_id`
/// in the body. Credentials are form-encoded before being joined, as required
/// by §2.3.1.
fn OAuth2Config::build_token_request(
  self : OAuth2Config,
  parameters : Array[(String, String)],
) -> TokenRequest {
  let body_parameters = parameters.copy()
  let headers : Array[(String, String)] = [
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("Accept", "application/json"),
  ]
  match self.client_secret {
    Some(secret) => {
      let credentials = form_encode(self.client_id) + ":" + form_encode(secret)
      headers.push(
        ("Authorization", "Basic " + @base64.encode(@utf8.encode(credentials))),
      )
    }
    None => body_parameters.push(("client_id", self.client_id))
  }
  {
    url: self.token_endpoint,
    http_method: "POST",
    headers,
    body: encode_form(body_parameters),
  }
}

///|
/// Builds the authorization code token request (RFC 6749 §4.1.3).
///
/// `redirect_uri` is always sent because the authorization request always
/// carried it, and the two values must match. When the authorization request
/// used PKCE, pass the same pair so that `code_verifier` is included.
pub fn OAuth2Config::authorization_code_request(
  self : OAuth2Config,
  code : StringView,
  pkce? : Pkce,
) -> TokenRequest raise OAuth2Error {
  require_parameter("code", code)
  let parameters : Array[(String, String)] = [
    ("grant_type", "authorization_code"),
    ("code", code.to_owned()),
    ("redirect_uri", self.redirect_uri),
  ]
  match pkce {
    Some(pkce) => parameters.push(("code_verifier", pkce.verifier()))
    None => ()
  }
  self.build_token_request(parameters)
}

///|
/// Builds a refresh token request (RFC 6749 §6).
///
/// The scope is intentionally omitted: asking for the original scope again is
/// allowed, but a server rejects any scope that was not granted, so the
/// request simply keeps whatever the refresh token already covers.
pub fn OAuth2Config::refresh_token_request(
  self : OAuth2Config,
  refresh_token : StringView,
) -> TokenRequest raise OAuth2Error {
  require_parameter("refresh_token", refresh_token)
  let parameters : Array[(String, String)] = [
    ("grant_type", "refresh_token"),
    ("refresh_token", refresh_token.to_owned()),
  ]
  self.build_token_request(parameters)
}

///|
/// Builds a client credentials token request (RFC 6749 §4.4).
///
/// This grant is only defined for confidential clients, so a configuration
/// without a client secret is rejected instead of producing a request that the
/// server would refuse.
pub fn OAuth2Config::client_credentials_request(
  self : OAuth2Config,
) -> TokenRequest raise OAuth2Error {
  if self.client_secret is None {
    raise InvalidConfiguration(
      "client_credentials requires a confidential client with a secret",
    )
  }
  let parameters : Array[(String, String)] = [
    ("grant_type", "client_credentials"),
  ]
  if self.scopes.length() > 0 {
    parameters.push(("scope", join_scopes(self.scopes)))
  }
  self.build_token_request(parameters)
}
