///|
/// Errors reported by the OAuth2 client package.
///
/// Configuration mistakes are separated from request and response errors so
/// that a caller can tell a programming error from a server or user error.
pub(all) suberror OAuth2Error {
  InvalidConfiguration(String)
  InvalidRequest(String)
  InvalidResponse(String)
}
