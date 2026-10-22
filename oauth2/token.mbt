///|
/// A successful token response (RFC 6749 §5.1).
pub struct Token {
  access_token : String
  token_type : String
  expires_in : Int64?
  refresh_token : String?
  scope : String?
  id_token : String?
}

///|
fn required_string(
  object : Map[String, Json],
  name : String,
) -> String raise OAuth2Error {
  match object.get(name) {
    Some(String(value)) => {
      if value.length() == 0 {
        raise InvalidResponse(name + " must not be empty")
      }
      value
    }
    Some(_) => raise InvalidResponse(name + " must be a string")
    None => raise InvalidResponse("token response is missing " + name)
  }
}

///|
fn optional_string(
  object : Map[String, Json],
  name : String,
) -> String? raise OAuth2Error {
  match object.get(name) {
    Some(String(value)) => Some(value)
    Some(_) => raise InvalidResponse(name + " must be a string")
    None => None
  }
}

///|
fn optional_seconds(
  object : Map[String, Json],
  name : String,
) -> Int64? raise OAuth2Error {
  match object.get(name) {
    Some(Number(value, ..)) => {
      if value < 0.0 || value.floor() != value {
        raise InvalidResponse(name + " must be a non-negative integer")
      }
      Some(value.to_int64())
    }
    Some(_) => raise InvalidResponse(name + " must be a number")
    None => None
  }
}

///|
/// Parses a token endpoint response.
///
/// `access_token` and `token_type` are required by RFC 6749 §5.1; everything
/// else is optional. `expires_in` must be a whole number of seconds so that a
/// caller does not accidentally treat a fractional value as an absolute time.
pub fn Token::from_json(json : Json) -> Token raise OAuth2Error {
  let object = match json {
    Object(object) => object
    _ => raise InvalidResponse("token response must be a JSON object")
  }
  {
    access_token: required_string(object, "access_token"),
    token_type: required_string(object, "token_type"),
    expires_in: optional_seconds(object, "expires_in"),
    refresh_token: optional_string(object, "refresh_token"),
    scope: optional_string(object, "scope"),
    id_token: optional_string(object, "id_token"),
  }
}

///|
/// The bearer token to present to a protected resource.
pub fn Token::access_token(self : Token) -> String {
  self.access_token
}

///|
/// The token type, normally `"Bearer"`.
pub fn Token::token_type(self : Token) -> String {
  self.token_type
}

///|
/// The access token lifetime in seconds, when the server reports one.
pub fn Token::expires_in(self : Token) -> Int64? {
  self.expires_in
}

///|
/// A refresh token, when the server issued one.
pub fn Token::refresh_token(self : Token) -> String? {
  self.refresh_token
}

///|
/// The granted scope, which may be narrower than the requested scope.
pub fn Token::scope(self : Token) -> String? {
  self.scope
}

///|
/// The OIDC ID token, when the request included `openid`.
pub fn Token::id_token(self : Token) -> String? {
  self.id_token
}
