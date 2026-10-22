///|
/// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2), the signature scheme behind
/// the JWS `RS256` algorithm (RFC 7518 §3.3).
///
/// Only the two components needed for signing and verification are kept:
/// the modulus `n`, the public exponent `e` and, for private keys, the private
/// exponent `d`. CRT parameters are parsed but not retained, because the
/// library has no constant-time CRT implementation to justify the extra state.
pub struct RsaPublicKey {
  modulus : @bigint.BigInt
  exponent : @bigint.BigInt
  size_bytes : Int32
}

///|
/// An RSA private key in PKCS#1 or PKCS#8 form.
pub struct RsaPrivateKey {
  modulus : @bigint.BigInt
  exponent : @bigint.BigInt
  private_exponent : @bigint.BigInt
  size_bytes : Int32
}

///|
/// DER encoding of the `DigestInfo` value for SHA-256 (RFC 8017 §9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX : Bytes = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

///|
/// OID value of `rsaEncryption` (1.2.840.113549.1.1.1) without its tag/length.
const RSA_ENCRYPTION_OID : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

///|
/// Sequential reader for the subset of DER used by RSA key encodings.
priv struct DerReader {
  bytes : Bytes
  mut offset : Int32
}

///|
fn DerReader::read_byte(self : DerReader) -> Int32 raise JwtError {
  if self.offset >= self.bytes.length() {
    raise InvalidKey("truncated DER structure")
  }
  let value = self.bytes[self.offset].to_int()
  self.offset += 1
  value
}

///|
/// Reads a DER length. Only the definite, minimally encoded form is accepted:
/// BER indefinite lengths (`0x80`) and non-minimal encodings are rejected so
/// that two different byte strings cannot parse to the same key.
fn DerReader::read_length(self : DerReader) -> Int32 raise JwtError {
  let first = self.read_byte()
  if first < 0x80 {
    return first
  }
  let count = first & 0x7F
  if count == 0 {
    raise InvalidKey("indefinite-length DER is not supported")
  }
  if count > 4 {
    raise InvalidKey("DER length field is too large")
  }
  let mut length = 0
  for _ in 0..<count {
    length = (length << 8) | self.read_byte()
  }
  if length < 0x80 {
    raise InvalidKey("DER length is not minimally encoded")
  }
  length
}

///|
/// Reads one tag-length-value triple and returns its tag and content bytes.
fn DerReader::read_tlv(self : DerReader) -> (Int32, Bytes) raise JwtError {
  let tag = self.read_byte()
  let length = self.read_length()
  if self.offset + length > self.bytes.length() {
    raise InvalidKey("DER element overflows its container")
  }
  let content = self.bytes[self.offset:self.offset + length].to_owned()
  self.offset += length
  (tag, content)
}

///|
/// Splits the content of a DER SEQUENCE into its top-level elements.
fn read_items(content : Bytes) -> Array[(Int32, Bytes)] raise JwtError {
  let reader : DerReader = { bytes: content, offset: 0, }
  let items : Array[(Int32, Bytes)] = []
  while reader.offset < content.length() {
    items.push(reader.read_tlv())
  }
  items
}

///|
/// Unwraps exactly one DER SEQUENCE and rejects trailing bytes.
fn unwrap_sequence(der : Bytes) -> Bytes raise JwtError {
  let reader : DerReader = { bytes: der, offset: 0, }
  let (tag, content) = reader.read_tlv()
  if tag != 0x30 {
    raise InvalidKey("key material is not a DER SEQUENCE")
  }
  if reader.offset != der.length() {
    raise InvalidKey("trailing data after the DER SEQUENCE")
  }
  content
}

///|
/// Reads a DER INTEGER as a non-negative big integer.
fn integer_of_item(item : (Int32, Bytes)) -> @bigint.BigInt raise JwtError {
  let (tag, content) = item
  if tag != 0x02 {
    raise InvalidKey("expected a DER INTEGER")
  }
  if content.length() == 0 {
    raise InvalidKey("DER INTEGER is empty")
  }
  if (content[0].to_int() & 0x80) != 0 {
    raise InvalidKey("RSA parameters must be non-negative")
  }
  @bigint.BigInt::from_octets(content)
}

///|
/// Checks whether an `AlgorithmIdentifier` sequence names `rsaEncryption`.
///
/// Without this check an EC or Ed25519 key would be misread as RSA, since only
/// the outer structure differs.
fn is_rsa_algorithm(algorithm : Bytes) -> Bool raise JwtError {
  let items = read_items(algorithm)
  if items.length() == 0 || items[0].0 != 0x06 {
    return false
  }
  items[0].1 == RSA_ENCRYPTION_OID
}

///|
/// Validates the numeric parameters shared by public and private keys.
///
/// RFC 7518 §3.3 requires RSA keys of at least 2048 bits for RS256, and
/// RFC 8017 requires a public exponent of at least 3 that is odd.
fn check_rsa_parameters(
  modulus : @bigint.BigInt,
  exponent : @bigint.BigInt,
) -> Int32 raise JwtError {
  let bits = modulus.bit_length()
  if bits < 2048 {
    raise InvalidKey("RSA modulus must be at least 2048 bits")
  }
  if exponent < 3 || exponent % 2 == 0 {
    raise InvalidKey("RSA public exponent must be an odd value of at least 3")
  }
  (bits + 7) / 8
}

///|
fn make_public_key(
  modulus : @bigint.BigInt,
  exponent : @bigint.BigInt,
) -> RsaPublicKey raise JwtError {
  let size_bytes = check_rsa_parameters(modulus, exponent)
  { modulus, exponent, size_bytes, }
}

///|
/// Number of bits in the modulus, useful for policy checks.
pub fn RsaPublicKey::modulus_bits(self : RsaPublicKey) -> Int32 {
  self.modulus.bit_length()
}

///|
/// Number of bits in the modulus of a private key.
pub fn RsaPrivateKey::modulus_bits(self : RsaPrivateKey) -> Int32 {
  self.modulus.bit_length()
}

///|
/// Extracts the public key matching a private key.
pub fn RsaPrivateKey::public_key(self : RsaPrivateKey) -> RsaPublicKey {
  {
    modulus: self.modulus,
    exponent: self.exponent,
    size_bytes: self.size_bytes,
  }
}

///|
/// Parses a PKCS#1 `RSAPublicKey` (`n`, `e`) or an SPKI `SubjectPublicKeyInfo`.
fn public_key_of_items(
  items : Array[(Int32, Bytes)],
) -> RsaPublicKey raise JwtError {
  if items.length() == 2 && items[0].0 == 0x02 && items[1].0 == 0x02 {
    return make_public_key(integer_of_item(items[0]), integer_of_item(items[1]))
  }
  if items.length() == 2 && items[0].0 == 0x30 && items[1].0 == 0x03 {
    if !is_rsa_algorithm(items[0].1) {
      raise InvalidKey("SubjectPublicKeyInfo is not an RSA key")
    }
    let bit_string = items[1].1
    if bit_string.length() == 0 || bit_string[0].to_int() != 0 {
      raise InvalidKey("SPKI BIT STRING must contain whole bytes")
    }
    let inner = read_items(unwrap_sequence(bit_string[1:].to_owned()))
    return public_key_of_items(inner)
  }
  raise InvalidKey("unsupported RSA public key encoding")
}

///|
/// Parses a PKCS#1 `RSAPrivateKey` or a PKCS#8 `PrivateKeyInfo`.
fn private_key_of_items(
  items : Array[(Int32, Bytes)],
) -> RsaPrivateKey raise JwtError {
  if items.length() >= 9 && items[0].0 == 0x02 && items[1].0 == 0x02 {
    let version = integer_of_item(items[0])
    if version != 0 && version != 1 {
      raise InvalidKey("unsupported RSA private key version")
    }
    let modulus = integer_of_item(items[1])
    let exponent = integer_of_item(items[2])
    let private_exponent = integer_of_item(items[3])
    let size_bytes = check_rsa_parameters(modulus, exponent)
    if private_exponent.is_zero() || private_exponent >= modulus {
      raise InvalidKey("RSA private exponent is out of range")
    }
    return { modulus, exponent, private_exponent, size_bytes, }
  }
  if items.length() >= 3 &&
    items[0].0 == 0x02 &&
    items[1].0 == 0x30 &&
    items[2].0 == 0x04 {
    if !is_rsa_algorithm(items[1].1) {
      raise InvalidKey("PKCS#8 key is not an RSA key")
    }
    let inner = read_items(unwrap_sequence(items[2].1))
    return private_key_of_items(inner)
  }
  raise InvalidKey("unsupported RSA private key encoding")
}

///|
/// Extracts the base64 payload of a PEM block, ignoring the label.
///
/// The label is deliberately not trusted: the DER structure decides whether the
/// material is a public or private key, so a mislabelled PEM cannot smuggle a
/// key type past the parser.
fn pem_to_der(pem : StringView) -> Bytes raise JwtError {
  let mut began = false
  let builder = StringBuilder()
  for raw_line in pem.split("\n") {
    let line = raw_line.trim()
    if line.has_prefix("-----BEGIN ") {
      began = true
      continue
    }
    if line.has_prefix("-----END ") {
      break
    }
    if began && line.length() > 0 {
      builder.write_stringview(line)
    }
  }
  if !began {
    raise InvalidKey("PEM data must contain a BEGIN marker")
  }
  @base64.decode(builder.to_string(), ignore_whitespace=true) catch {
    _ => raise InvalidKey("PEM body is not valid base64")
  }
}

///|
/// Builds an RSA public key from its big-endian components.
///
/// This is the entry point for JWK keys (RFC 7517), whose `n` and `e` members
/// are base64url-encoded big-endian integers. The same parameter checks as PEM
/// parsing apply, so a weak JWK is rejected exactly like a weak PEM file.
pub fn RsaPublicKey::from_components(
  modulus : BytesView,
  exponent : BytesView,
) -> RsaPublicKey raise JwtError {
  if modulus.length() == 0 {
    raise InvalidKey("RSA modulus must not be empty")
  }
  if exponent.length() == 0 {
    raise InvalidKey("RSA public exponent must not be empty")
  }
  make_public_key(
    @bigint.BigInt::from_octets(modulus),
    @bigint.BigInt::from_octets(exponent),
  )
}

///|
/// Parses a PEM-encoded RSA public key.
///
/// Accepts `-----BEGIN PUBLIC KEY-----` (SPKI, the common `openssl rsa -pubout`
/// output) and `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1).
pub fn RsaPublicKey::from_pem(pem : StringView) -> RsaPublicKey raise JwtError {
  public_key_of_items(read_items(unwrap_sequence(pem_to_der(pem))))
}

///|
/// Parses a PEM-encoded RSA private key.
///
/// Accepts `-----BEGIN PRIVATE KEY-----` (PKCS#8, the default of OpenSSL 3)
/// and `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1).
pub fn RsaPrivateKey::from_pem(
  pem : StringView,
) -> RsaPrivateKey raise JwtError {
  private_key_of_items(read_items(unwrap_sequence(pem_to_der(pem))))
}

///|
/// Builds the EMSA-PKCS1-v1_5 encoded message for SHA-256 (RFC 8017 §9.2).
fn pkcs1_v1_5_encode(message : BytesView, length : Int32) -> Bytes {
  let digest = sha256(message)
  let encoded_digest_length = SHA256_DIGEST_INFO_PREFIX.length() +
    digest.length()
  let padding_length = length - encoded_digest_length - 3
  let buffer = @buffer.Buffer(size_hint=length)
  buffer.write_byte(b'\x00')
  buffer.write_byte(b'\x01')
  for _ in 0..<padding_length {
    buffer.write_byte(b'\xff')
  }
  buffer.write_byte(b'\x00')
  buffer.write_bytes(SHA256_DIGEST_INFO_PREFIX)
  buffer.write_bytes(digest)
  buffer.to_bytes()
}

///|
/// Signs a message with RSASSA-PKCS1-v1_5 and SHA-256.
///
/// The returned signature always has the same length as the modulus, as
/// required by RFC 8017 and assumed by JWS verifiers.
pub fn RsaPrivateKey::sign_sha256(
  self : RsaPrivateKey,
  message : BytesView,
) -> Bytes {
  let encoded = pkcs1_v1_5_encode(message, self.size_bytes)
  let m = @bigint.BigInt::from_octets(encoded)
  let s = m.pow(self.private_exponent, modulus=self.modulus)
  s.to_octets(length=self.size_bytes)
}

///|
/// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature.
///
/// Returns `false` (rather than raising) for any malformed signature, so a
/// caller cannot distinguish "wrong signature" from "bad encoding": both are
/// simply not authentic.
pub fn RsaPublicKey::verify_sha256(
  self : RsaPublicKey,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  if signature.length() != self.size_bytes {
    return false
  }
  let s = @bigint.BigInt::from_octets(signature)
  if s >= self.modulus {
    return false
  }
  let m = s.pow(self.exponent, modulus=self.modulus)
  let encoded = m.to_octets(length=self.size_bytes)
  constant_time_equal(encoded, pkcs1_v1_5_encode(message, self.size_bytes))
}
