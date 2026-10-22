///|
/// JWT signing algorithms supported by moonjwt.
///
/// The `alg` header of every JWT must be one of these values. Unsupported
/// algorithms are rejected explicitly instead of falling back to `none`,
/// which prevents the classic algorithm-confusion attack.
pub enum Algorithm {
  HS256
  RS256
}

///|
/// Returns the JOSE identifier of an algorithm, as registered by RFC 7518.
pub fn Algorithm::name(self : Algorithm) -> String {
  match self {
    HS256 => "HS256"
    RS256 => "RS256"
  }
}

///|
/// Parses a JOSE algorithm identifier. Returns `None` for algorithms that
/// moonjwt does not implement.
pub fn Algorithm::from_name(name : String) -> Algorithm? {
  match name {
    "HS256" => Some(HS256)
    "RS256" => Some(RS256)
    _ => None
  }
}
