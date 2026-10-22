///|
/// OAuth2 grant types supported by the MVP client.
pub(all) enum GrantType {
  AuthorizationCode
  ClientCredentials
  RefreshToken
}

///|
/// Every grant type this client understands.
pub fn GrantType::all() -> Array[GrantType] {
  [AuthorizationCode, ClientCredentials, RefreshToken]
}

///|
/// Returns the wire value of a grant type (RFC 6749 §4).
pub fn GrantType::value(self : GrantType) -> String {
  match self {
    AuthorizationCode => "authorization_code"
    ClientCredentials => "client_credentials"
    RefreshToken => "refresh_token"
  }
}
