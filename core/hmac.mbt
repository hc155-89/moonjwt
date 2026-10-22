///|
/// HMAC-SHA256 (RFC 2104, RFC 7518 §3.2).
///
/// `key` may be longer than the 64-byte block size; in that case it is hashed
/// first, exactly as the RFC requires.
pub fn hmac_sha256(key : BytesView, message : BytesView) -> Bytes {
  let key_block : Array[Byte] = Array::make(64, 0)
  if key.length() > 64 {
    let hashed_key = sha256(key)
    for i in 0..<hashed_key.length() {
      key_block[i] = hashed_key[i]
    }
  } else {
    for i in 0..<key.length() {
      key_block[i] = key[i]
    }
  }
  let inner = @buffer.Buffer(size_hint=64 + message.length())
  for i in 0..<64 {
    inner.write_byte((key_block[i].to_uint() ^ 0x36).to_byte())
  }
  inner.write_bytes(message)
  let inner_digest = sha256(inner.to_bytes())
  let outer = @buffer.Buffer(size_hint=96)
  for i in 0..<64 {
    outer.write_byte((key_block[i].to_uint() ^ 0x5c).to_byte())
  }
  outer.write_bytes(inner_digest)
  sha256(outer.to_bytes())
}
