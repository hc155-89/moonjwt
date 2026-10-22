///|
/// Well-known discovery path defined by OpenID Connect Discovery 1.0 §4.
pub let discovery_path : String = "/.well-known/openid-configuration"

///|
/// JWKS location relative to an issuer is not fixed by the spec, so the
/// discovery document is the authoritative source. This constant is only a
/// fallback used by small, spec-compliant providers.
pub let default_jwks_path : String = "/.well-known/jwks.json"
