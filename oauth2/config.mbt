///|
/// An OAuth2 client registration (RFC 6749 §2).
pub struct OAuth2Config {
  authorization_endpoint : String
  token_endpoint : String
  client_id : String
  client_secret : String?
  redirect_uri : String
  scopes : Array[String]
}

///|
fn require_non_empty(
  name : String,
  value : StringView,
) -> Unit raise OAuth2Error {
  if value.trim().length() == 0 {
    raise InvalidConfiguration(name + " must not be empty")
  }
}

///|
/// Creates a client configuration.
///
/// The client secret is optional so that public clients (SPAs, native apps)
/// can use the authorization code flow with PKCE, which RFC 6749 §2.1 defines
/// as a client that cannot keep a secret.
pub fn OAuth2Config::new(
  authorization_endpoint : StringView,
  token_endpoint : StringView,
  client_id : StringView,
  redirect_uri : StringView,
) -> OAuth2Config raise OAuth2Error {
  require_non_empty("authorization_endpoint", authorization_endpoint)
  require_non_empty("token_endpoint", token_endpoint)
  require_non_empty("client_id", client_id)
  require_non_empty("redirect_uri", redirect_uri)
  {
    authorization_endpoint: authorization_endpoint.to_owned(),
    token_endpoint: token_endpoint.to_owned(),
    client_id: client_id.to_owned(),
    client_secret: None,
    redirect_uri: redirect_uri.to_owned(),
    scopes: [],
  }
}

///|
/// Returns a copy of the configuration carrying a client secret.
pub fn OAuth2Config::with_client_secret(
  self : OAuth2Config,
  secret : StringView,
) -> OAuth2Config raise OAuth2Error {
  require_non_empty("client_secret", secret)
  {
    authorization_endpoint: self.authorization_endpoint,
    token_endpoint: self.token_endpoint,
    client_id: self.client_id,
    client_secret: Some(secret.to_owned()),
    redirect_uri: self.redirect_uri,
    scopes: self.scopes,
  }
}

///|
/// Returns a copy of the configuration with the default scope list replaced.
pub fn OAuth2Config::with_scopes(
  self : OAuth2Config,
  scopes : Array[String],
) -> OAuth2Config {
  {
    authorization_endpoint: self.authorization_endpoint,
    token_endpoint: self.token_endpoint,
    client_id: self.client_id,
    client_secret: self.client_secret,
    redirect_uri: self.redirect_uri,
    scopes,
  }
}

///|
/// The authorization endpoint URL.
pub fn OAuth2Config::authorization_endpoint(self : OAuth2Config) -> String {
  self.authorization_endpoint
}

///|
/// The token endpoint URL.
pub fn OAuth2Config::token_endpoint(self : OAuth2Config) -> String {
  self.token_endpoint
}

///|
/// The registered client identifier.
pub fn OAuth2Config::client_id(self : OAuth2Config) -> String {
  self.client_id
}

///|
/// The client secret, absent for public clients.
pub fn OAuth2Config::client_secret(self : OAuth2Config) -> String? {
  self.client_secret
}

///|
/// The redirect URI registered with the authorization server.
pub fn OAuth2Config::redirect_uri(self : OAuth2Config) -> String {
  self.redirect_uri
}

///|
/// The default scope list.
pub fn OAuth2Config::scopes(self : OAuth2Config) -> Array[String] {
  self.scopes
}

///|
/// Parameters that the authorization URL builder controls itself. Allowing a
/// caller to add them again would let an extra parameter silently override the
/// request type, client, redirect URI, state or PKCE challenge.
fn is_reserved_parameter(name : String) -> Bool {
  match name {
    "response_type"
    | "client_id"
    | "redirect_uri"
    | "scope"
    | "state"
    | "code_challenge"
    | "code_challenge_method"
    | "nonce"
    | "grant_type" => true
    _ => false
  }
}

///|
/// Options for an authorization code request (RFC 6749 §4.1.1, RFC 7636).
pub struct AuthCodeOptions {
  state : String
  nonce : String?
  scopes : Array[String]
  pkce : Pkce?
  extra_parameters : Array[(String, String)]
}

///|
/// Creates authorization code options.
///
/// `state` is mandatory: it is the only client-side defence against login CSRF
/// (RFC 6749 §10.12), so an empty value is rejected instead of silently
/// producing an unprotected request.
pub fn AuthCodeOptions::new(
  state : StringView,
) -> AuthCodeOptions raise OAuth2Error {
  require_non_empty("state", state)
  {
    state: state.to_owned(),
    nonce: None,
    scopes: [],
    pkce: None,
    extra_parameters: [],
  }
}

///|
/// Returns a copy of the options carrying an OIDC `nonce`.
pub fn AuthCodeOptions::with_nonce(
  self : AuthCodeOptions,
  nonce : StringView,
) -> AuthCodeOptions raise OAuth2Error {
  require_non_empty("nonce", nonce)
  {
    state: self.state,
    nonce: Some(nonce.to_owned()),
    scopes: self.scopes,
    pkce: self.pkce,
    extra_parameters: self.extra_parameters,
  }
}

///|
/// Returns a copy of the options with the per-request scope list replaced.
pub fn AuthCodeOptions::with_scopes(
  self : AuthCodeOptions,
  scopes : Array[String],
) -> AuthCodeOptions {
  {
    state: self.state,
    nonce: self.nonce,
    scopes,
    pkce: self.pkce,
    extra_parameters: self.extra_parameters,
  }
}

///|
/// Returns a copy of the options carrying a PKCE pair.
pub fn AuthCodeOptions::with_pkce(
  self : AuthCodeOptions,
  pkce : Pkce,
) -> AuthCodeOptions {
  {
    state: self.state,
    nonce: self.nonce,
    scopes: self.scopes,
    pkce: Some(pkce),
    extra_parameters: self.extra_parameters,
  }
}

///|
/// Returns a copy of the options with one additional query parameter.
///
/// Reserved parameters are rejected so that an extra parameter cannot replace
/// the ones generated from the typed fields.
pub fn AuthCodeOptions::with_parameter(
  self : AuthCodeOptions,
  name : StringView,
  value : StringView,
) -> AuthCodeOptions raise OAuth2Error {
  require_non_empty("parameter name", name)
  if is_reserved_parameter(name.to_owned()) {
    raise InvalidRequest(
      "parameter \"" + name.to_owned() + "\" is generated automatically",
    )
  }
  let extra_parameters = self.extra_parameters.copy()
  extra_parameters.push((name.to_owned(), value.to_owned()))
  {
    state: self.state,
    nonce: self.nonce,
    scopes: self.scopes,
    pkce: self.pkce,
    extra_parameters,
  }
}

///|
/// The CSRF state value carried by the request.
pub fn AuthCodeOptions::state(self : AuthCodeOptions) -> String {
  self.state
}

///|
/// The OIDC nonce carried by the request.
pub fn AuthCodeOptions::nonce(self : AuthCodeOptions) -> String? {
  self.nonce
}

///|
/// The PKCE pair carried by the request.
pub fn AuthCodeOptions::pkce(self : AuthCodeOptions) -> Pkce? {
  self.pkce
}

///|
fn append_query(
  builder : StringBuilder,
  separator : String,
  name : StringView,
  value : StringView,
) -> Unit {
  builder.write_string(separator)
  builder.write_string(percent_encode(name))
  builder.write_char('=')
  builder.write_string(percent_encode(value))
}

///|
fn join_scopes(scopes : Array[String]) -> String {
  let builder = StringBuilder()
  let mut first = true
  for scope in scopes {
    if !first {
      builder.write_char(' ')
    }
    builder.write_string(scope)
    first = false
  }
  builder.to_string()
}

///|
/// Builds the authorization URL for the authorization code flow.
///
/// The query is emitted in a fixed order so that the output is deterministic
/// and easy to test. When the configured endpoint already has a query string,
/// parameters are appended with `&` instead of `?`.
pub fn OAuth2Config::authorization_url(
  self : OAuth2Config,
  options : AuthCodeOptions,
) -> String {
  let builder = StringBuilder()
  builder.write_string(self.authorization_endpoint)
  let separator = if self.authorization_endpoint.contains("?") {
    "&"
  } else {
    "?"
  }
  append_query(builder, separator, "response_type", "code")
  append_query(builder, "&", "client_id", self.client_id)
  append_query(builder, "&", "redirect_uri", self.redirect_uri)
  let scopes = if options.scopes.is_empty() {
    self.scopes
  } else {
    options.scopes
  }
  if scopes.length() > 0 {
    append_query(builder, "&", "scope", join_scopes(scopes))
  }
  append_query(builder, "&", "state", options.state)
  match options.pkce {
    Some(pkce) => {
      append_query(builder, "&", "code_challenge", pkce.challenge)
      append_query(
        builder,
        "&",
        "code_challenge_method",
        pkce.transformation.value(),
      )
    }
    None => ()
  }
  match options.nonce {
    Some(nonce) => append_query(builder, "&", "nonce", nonce)
    None => ()
  }
  for parameter in options.extra_parameters {
    append_query(builder, "&", parameter.0, parameter.1)
  }
  builder.to_string()
}
