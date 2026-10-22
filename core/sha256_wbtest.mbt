///|
test "sha256 fips 180-4 vectors" {
  assert_eq(
    @hex.encode(sha256(b"")),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    @hex.encode(sha256(b"abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(
    @hex.encode(
      sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "hmac sha256 rfc 4231 case 1" {
  let key = Bytes::make(20, 0x0b)
  assert_eq(
    @hex.encode(hmac_sha256(key, b"Hi There")),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
}

///|
test "hmac sha256 rfc 4231 case 2" {
  assert_eq(
    @hex.encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
}

///|
test "hmac sha256 rfc 4231 case 3" {
  let key = Bytes::make(20, 0xaa)
  let data = Bytes::make(50, 0xdd)
  assert_eq(
    @hex.encode(hmac_sha256(key, data)),
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  )
}

///|
test "hmac sha256 rfc 4231 case 4" {
  let key = Bytes::makei(25, i => (i + 1).to_byte())
  let data = Bytes::make(50, 0xcd)
  assert_eq(
    @hex.encode(hmac_sha256(key, data)),
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
  )
}

///|
test "hmac sha256 rfc 4231 case 6 hashes long keys" {
  let key = Bytes::make(131, 0xaa)
  let data = b"Test Using Larger Than Block-Size Key - Hash Key First"
  assert_eq(
    @hex.encode(hmac_sha256(key, data)),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  )
}

///|
test "hmac sha256 rfc 4231 case 7 hashes long keys and data" {
  let key = Bytes::make(131, 0xaa)
  let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
  assert_eq(
    @hex.encode(hmac_sha256(key, data)),
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
  )
}
