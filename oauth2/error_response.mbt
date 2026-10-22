///|
/// An OAuth2 token endpoint error response (RFC 6749 §5.2).
///
/// Servers report failures with HTTP 400 (or 401) and a JSON body whose `error`
/// member is a registered code such as `invalid_grant`. Parsing that body gives
/// callers a stable code to branch on instead of matching on prose.
pub struct OAuth2ErrorResponse {
  error : String
  description : String?
  uri : String?
}

///|
/// Parses an error response body.
///
/// `error` is mandatory and must be a non-empty string. `error_description` and
/// `error_uri` are optional and are never interpreted as machine-readable
/// values, so their wording cannot change control flow.
pub fn OAuth2ErrorResponse::from_json(
  json : Json,
) -> OAuth2ErrorResponse raise OAuth2Error {
  let object = match json {
    Object(object) => object
    _ => raise InvalidResponse("token error response must be a JSON object")
  }
  let error = match object.get("error") {
    Some(String(value)) => {
      if value.trim().length() == 0 {
        raise InvalidResponse("\"error\" must not be empty")
      }
      value
    }
    Some(_) => raise InvalidResponse("\"error\" must be a string")
    None => raise InvalidResponse("token error response is missing \"error\"")
  }
  let description = optional_field(object, "error_description")
  let uri = optional_field(object, "error_uri")
  { error, description, uri, }
}

///|
fn optional_field(
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
/// The registered error code, for example `"invalid_grant"`.
pub fn OAuth2ErrorResponse::error(self : OAuth2ErrorResponse) -> String {
  self.error
}

///|
/// The human-readable description, when the server sent one.
pub fn OAuth2ErrorResponse::description(self : OAuth2ErrorResponse) -> String? {
  self.description
}

///|
/// The URI identifying the error, when the server sent one.
pub fn OAuth2ErrorResponse::uri(self : OAuth2ErrorResponse) -> String? {
  self.uri
}

///|
/// Whether the error means the authorization grant must be obtained again.
///
/// RFC 6749 §5.2 defines `invalid_grant` as an expired, revoked or otherwise
/// invalid authorization code or refresh token, which is exactly the case where
/// retrying token exchange with the same grant cannot succeed.
pub fn OAuth2ErrorResponse::requires_new_grant(
  self : OAuth2ErrorResponse,
) -> Bool {
  self.error == "invalid_grant"
}
