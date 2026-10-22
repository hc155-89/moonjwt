///|
/// Decoded JOSE header (RFC 7515 §4.1).
///
/// Only the fields moonjwt understands are surfaced; unknown header
/// parameters are intentionally dropped instead of being trusted.
pub struct Header {
  alg : Algorithm
  typ : String
  kid : String?
}

///|
/// Creates a header for the given algorithm.
///
/// `typ` defaults to `"JWT"`, which is the registered media type for JWTs
/// (RFC 7519 §5.1). Use `with_kid` when a JWKS contains multiple keys.
pub fn Header::new(alg : Algorithm) -> Header {
  { alg, typ: "JWT", kid: None, }
}

///|
/// Returns a copy of the header carrying a key identifier.
pub fn Header::with_kid(self : Header, kid : String) -> Header {
  { alg: self.alg, typ: self.typ, kid: Some(kid), }
}

///|
/// Serializes the header to a JSON object.
pub fn Header::to_json(self : Header) -> Json {
  let object : Map[String, Json] = Map([])
  object.set("alg", Json::string(self.alg.name()))
  object.set("typ", Json::string(self.typ))
  match self.kid {
    Some(kid) => object.set("kid", Json::string(kid))
    None => ()
  }
  Json::object(object)
}

///|
/// Parses a JOSE header from JSON.
///
/// A missing `alg` field, a non-string field, or an algorithm moonjwt does not
/// implement is rejected. In particular `"none"` is never accepted, closing
/// the algorithm-confusion hole described in RFC 8725 §2.1.
pub fn Header::from_json(json : Json) -> Header raise JwtError {
  let object = match json {
    Object(object) => object
    _ => raise InvalidHeader("header must be a JSON object")
  }
  let alg_name = match object.get("alg") {
    Some(String(name)) => name
    Some(_) => raise InvalidHeader("\"alg\" must be a string")
    None => raise InvalidHeader("header is missing \"alg\"")
  }
  let alg = match Algorithm::from_name(alg_name) {
    Some(alg) => alg
    None => raise UnsupportedAlgorithm(alg_name)
  }
  let typ = match object.get("typ") {
    Some(String(value)) => value
    Some(_) => raise InvalidHeader("\"typ\" must be a string")
    None => "JWT"
  }
  let kid = match object.get("kid") {
    Some(String(value)) => Some(value)
    Some(_) => raise InvalidHeader("\"kid\" must be a string")
    None => None
  }
  { alg, typ, kid, }
}

///|
/// JWT claims set (RFC 7519 §3).
///
/// The claims are kept in their JSON representation so that application
/// specific claims survive a decode/encode round trip without a schema.
pub struct Payload {
  claims : Map[String, Json]
}

///|
/// Creates an empty claims set.
pub fn Payload::new() -> Payload {
  { claims: Map([]), }
}

///|
/// Creates a claims set from a JSON object.
pub fn Payload::from_json(json : Json) -> Payload raise JwtError {
  match json {
    Object(claims) => { claims, }
    _ => raise InvalidJson("JWT payload must be a JSON object")
  }
}

///|
/// Serializes the claims set back to JSON.
pub fn Payload::to_json(self : Payload) -> Json {
  Json::object(self.claims)
}

///|
/// Sets a claim, replacing any previous value.
pub fn Payload::set(self : Payload, key : String, value : Json) -> Unit {
  self.claims.set(key, value)
}

///|
/// Reads a claim without removing it.
pub fn Payload::get(self : Payload, key : String) -> Json? {
  self.claims.get(key)
}

///|
/// Returns whether a claim is present.
pub fn Payload::contains(self : Payload, key : String) -> Bool {
  self.claims.contains(key)
}

///|
/// Number of claims in the payload.
pub fn Payload::length(self : Payload) -> Int32 {
  self.claims.length()
}
