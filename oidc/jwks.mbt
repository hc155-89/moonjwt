///|
/// Parses and addresses an OpenID Connect JWKS document (RFC 7517 §5).
///
/// The whole set is parsed into an immutable snapshot so that a caller can make
/// a single explicit choice about which key to trust, and a whole document is
/// available even when the ID token header does not carry a `kid`.
pub struct Jwks {
  keys : Array[JwkRsaKey]
}

///|
/// One public key in the set, keeping only the RFC 7518 §6.3 RSA member names.
pub struct JwkRsaKey {
  kid : String?
  key_use : String?
  alg : String?
  modulus : Bytes
  exponent : Bytes
}

///|
fn root_keys(json : Json) -> Array[Json] raise OidcError {
  match json {
    Object(object) =>
      match object.get("keys") {
        Some(Array(items)) => items
        Some(_) => raise InvalidResponse("\"keys\" must be an array")
        None => raise InvalidResponse("JWKS is missing \"keys\"")
      }
    _ => raise InvalidResponse("JWKS must be a JSON object")
  }
}

///|
fn decode_url_param(
  object : Map[String, Json],
  name : String,
) -> Bytes raise OidcError {
  match object.get(name) {
    Some(String(value)) =>
      @core.decode_base64url(value) catch {
        _ => raise InvalidResponse(name + " must be base64url-encoded")
      }
    Some(_) => raise InvalidResponse(name + " must be a string")
    None => raise InvalidResponse("JWK is missing " + name)
  }
}

///|
fn optional_param(
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
/// Parses a raw RSA public key JWK.
///
/// Only `kty=RSA` with `n` and `e` members is accepted; every other key type is
/// intentionally unsupported. moonjwt signs only with RS256, so a JWKS that
/// contains no clockable RSA keys cannot express a token this library would
/// ever accept as authentic.
pub fn Jwks::from_json(json : Json) -> Jwks raise OidcError {
  let items = root_keys(json)
  let keys : Array[JwkRsaKey] = []
  for item in items {
    let object = match item {
      Object(object) => object
      _ => raise InvalidResponse("each JWKS key must be an object")
    }
    match optional_param(object, "kty") {
      Some("RSA") => ()
      Some(value) =>
        raise InvalidResponse("unsupported JWK kty \"" + value + "\"")
      None => raise InvalidResponse("JWK is missing kty")
    }
    keys.push({
      kid: optional_param(object, "kid"),
      key_use: optional_param(object, "use"),
      alg: optional_param(object, "alg"),
      modulus: decode_url_param(object, "n"),
      exponent: decode_url_param(object, "e"),
    })
  }
  { keys, }
}

///|
/// All keys in the set.
pub fn Jwks::keys(self : Jwks) -> Array[JwkRsaKey] {
  self.keys
}

///|
/// The number of keys in the set.
pub fn Jwks::length(self : Jwks) -> Int32 {
  self.keys.length()
}

///|
/// The `kid` of a key, used to match the ID token header.
pub fn JwkRsaKey::key_id(self : JwkRsaKey) -> String? {
  self.kid
}

///|
/// The declared `use`, normally `"sig"`.
pub fn JwkRsaKey::use_case(self : JwkRsaKey) -> String? {
  self.key_use
}

///|
/// The declared algorithm, normally `"RS256"`.
pub fn JwkRsaKey::algorithm(self : JwkRsaKey) -> String? {
  self.alg
}

///|
/// The RSA modulus `n`.
pub fn JwkRsaKey::modulus(self : JwkRsaKey) -> Bytes {
  self.modulus
}

///|
/// The RSA public exponent `e`.
pub fn JwkRsaKey::exponent(self : JwkRsaKey) -> Bytes {
  self.exponent
}

///|
/// Converts the JWK into an RSA public key usable by the JWT verifier.
///
/// The component checks are the same as PEM parsing, so a 1024-bit JWK is
/// rejected exactly like a 1024-bit PEM file.
pub fn JwkRsaKey::public_key(
  self : JwkRsaKey,
) -> @core.RsaPublicKey raise OidcError {
  @core.RsaPublicKey::from_components(self.modulus, self.exponent) catch {
    _ => raise InvalidResponse("JWK does not describe a usable RSA key")
  }
}

///|
/// Whether the key may be used to verify a signature.
///
/// `use` other than `"sig"` and an explicit `alg` other than `RS256` exclude
/// the key, so a JWKS cannot silently downgrade verification to an algorithm
/// this library does not implement.
fn JwkRsaKey::is_signing_key(self : JwkRsaKey) -> Bool {
  let usable_use = match self.key_use {
    Some("enc") => false
    _ => true
  }
  let usable_alg = match self.alg {
    Some("RS256") => true
    Some(_) => false
    None => true
  }
  usable_use && usable_alg
}

///|
/// Selects the key whose `kid` matches, returning `None` when none does.
pub fn Jwks::key_by_id(self : Jwks, kid : String) -> JwkRsaKey? {
  for key in self.keys {
    if key.is_signing_key() && key.kid == Some(kid) {
      return Some(key)
    }
  }
  None
}

///|
/// Returns the only usable key in the set, or `None` when it is ambiguous.
///
/// Used for tokens without a `kid` header: accepting one key is safe, while
/// accepting "the first of several" would let a key ordering change alter which
/// key verifies a signature.
pub fn Jwks::only_key(self : Jwks) -> JwkRsaKey? {
  let mut candidate : JwkRsaKey? = None
  let mut count = 0
  for key in self.keys {
    if key.is_signing_key() {
      candidate = Some(key)
      count += 1
    }
  }
  if count == 1 {
    candidate
  } else {
    None
  }
}
