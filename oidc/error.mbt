///|
/// Errors raised while reading OIDC documents or validating an ID token.
///
/// The variants mirror the failure stages: a malformed document is an
/// `InvalidResponse`, a document that is missing something moonjwt needs is an
/// `InvalidConfiguration`, and a token that fails any check is an
/// `InvalidIdToken`.
pub(all) suberror OidcError {
  InvalidConfiguration(String)
  InvalidResponse(String)
  InvalidIdToken(String)
}
