///|
/// SHA-256 constants from FIPS 180-4 §4.2.2.
fn sha256_k() -> Array[UInt32] {
  [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ]
}

///|
/// Rotates a 32-bit word right by `n` bits.
fn sha256_rotr(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// SHA-256 message digest (FIPS 180-4).
///
/// Implemented in pure MoonBit so it works identically on the Wasm, JS and
/// native backends without any FFI or host crypto provider.
pub fn sha256(message : BytesView) -> Bytes {
  let bit_length : Int64 = message.length().to_int64() * 8
  // One 0x80 byte, zero padding, then the 64-bit big-endian bit length.
  let padded_length = (message.length() + 9 + 63) / 64 * 64
  let padding = @buffer.Buffer(size_hint=padded_length)
  padding.write_bytes(message)
  padding.write_byte(0x80)
  for _ in 0..<(padded_length - message.length() - 9) {
    padding.write_byte(0)
  }
  padding.write_int64_be(bit_length)
  let data = padding.to_bytes()

  let k = sha256_k()
  let w : Array[UInt32] = Array::make(64, 0)
  let mut h0 : UInt32 = 0x6a09e667
  let mut h1 : UInt32 = 0xbb67ae85
  let mut h2 : UInt32 = 0x3c6ef372
  let mut h3 : UInt32 = 0xa54ff53a
  let mut h4 : UInt32 = 0x510e527f
  let mut h5 : UInt32 = 0x9b05688c
  let mut h6 : UInt32 = 0x1f83d9ab
  let mut h7 : UInt32 = 0x5be0cd19

  let blocks = data.length() / 64
  for block in 0..<blocks {
    for j in 0..<16 {
      let offset = block * 64 + j * 4
      w[j] = (data[offset].to_uint() << 24) |
        (data[offset + 1].to_uint() << 16) |
        (data[offset + 2].to_uint() << 8) |
        data[offset + 3].to_uint()
    }
    for j in 16..<64 {
      let x = w[j - 15]
      let y = w[j - 2]
      let s0 = sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3)
      let s1 = sha256_rotr(y, 17) ^ sha256_rotr(y, 19) ^ (y >> 10)
      w[j] = w[j - 16] + s0 + w[j - 7] + s1
    }
    let mut a = h0
    let mut b = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    let mut f = h5
    let mut g = h6
    let mut h = h7
    for j in 0..<64 {
      let s1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25)
      let ch = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
      let temp1 = h + s1 + ch + k[j] + w[j]
      let s0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 + maj
      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
    }
    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
    h5 = h5 + f
    h6 = h6 + g
    h7 = h7 + h
  }

  let digest = @buffer.Buffer(size_hint=32)
  digest.write_uint_be(h0)
  digest.write_uint_be(h1)
  digest.write_uint_be(h2)
  digest.write_uint_be(h3)
  digest.write_uint_be(h4)
  digest.write_uint_be(h5)
  digest.write_uint_be(h6)
  digest.write_uint_be(h7)
  digest.to_bytes()
}
