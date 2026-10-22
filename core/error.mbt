///|
/// Errors produced by the core JWT package.
///
/// Every fallible public API in moonjwt reports one of these variants so that
/// callers can distinguish malformed input from unsupported algorithms.
pub(all) suberror JwtError {
  InvalidBase64Url(String)
  InvalidJson(String)
  InvalidHeader(String)
  UnsupportedAlgorithm(String)
  InvalidToken(String)
  InvalidSignature
}
