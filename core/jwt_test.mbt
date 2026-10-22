///|
fn rejects_unsupported(token : String) -> Bool {
  try {
    ignore(@core.decode(token, "secret"))
    false
  } catch {
    @core.UnsupportedAlgorithm(_) => true
    _ => false
  }
}

///|
test "hs256 round trip preserves custom claims" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("alice"))
  payload.set("admin", Json::boolean(true))
  payload.set("roles", Json::array([Json::string("user")]))
  let token = @core.encode(payload, "correct horse battery staple") catch {
    _ => panic()
  }
  assert_eq(Array::from_iter(token.split(".")).length(), 3)
  let decoded = @core.decode(token, "correct horse battery staple") catch {
    _ => panic()
  }
  assert_eq(decoded.header().algorithm().name(), "HS256")
  assert_eq(decoded.header().media_type(), "JWT")
  assert_true(decoded.payload().get("sub") == Some(Json::string("alice")))
  assert_true(decoded.payload().get("admin") == Some(Json::boolean(true)))
}

///|
test "hs256 supports key ids" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("bob"))
  let header = @core.Header::new(@core.HS256).with_kid("key-2026")
  let token = @core.encode_with_header(payload, header, b"secret") catch {
    _ => panic()
  }
  let decoded = @core.decode_with_key(token, b"secret") catch { _ => panic() }
  assert_true(decoded.header().key_id() == Some("key-2026"))
  assert_true(decoded.payload().get("sub") == Some(Json::string("bob")))
}

///|
test "hs256 rejects a wrong secret" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("alice"))
  let token = @core.encode(payload, "right") catch { _ => panic() }
  let rejected = try {
    ignore(@core.decode(token, "wrong"))
    false
  } catch {
    @core.InvalidSignature => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "hs256 rejects a tampered signature" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("alice"))
  let token = @core.encode(payload, "secret") catch { _ => panic() }
  let segments = Array::from_iter(token.split("."))
  let tampered = segments[0].to_owned() +
    "." +
    segments[1].to_owned() +
    "." +
    @core.encode_base64url(b"forged")
  let rejected = try {
    ignore(@core.decode_with_key(tampered, b"secret"))
    false
  } catch {
    @core.InvalidSignature => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "hs256 rejects malformed compact serialization" {
  let two_parts = try {
    ignore(@core.decode("aaa.bbb", "secret"))
    false
  } catch {
    @core.InvalidToken(_) => true
    _ => false
  }
  let four_parts = try {
    ignore(@core.decode("a.b.c.d", "secret"))
    false
  } catch {
    @core.InvalidToken(_) => true
    _ => false
  }
  assert_true(two_parts)
  assert_true(four_parts)
}

///|
test "decode rejects unsupported algorithms before verifying" {
  let header = @core.encode_base64url_text(
    "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
  )
  let payload = @core.encode_base64url_text("{\"sub\":\"alice\"}")
  assert_true(rejects_unsupported(header + "." + payload + ".AAAA"))
  let none_header = @core.encode_base64url_text("{\"alg\":\"none\"}")
  assert_true(rejects_unsupported(none_header + "." + payload + "."))
}

///|
test "decode rejects invalid base64url segments" {
  let rejected = try {
    ignore(@core.decode("not+base64url.also-not.sig", "secret"))
    false
  } catch {
    @core.InvalidBase64Url(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "rfc 7519 appendix a.1 hs256 vector verifies" {
  let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let key = @core.decode_base64url(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  ) catch {
    _ => panic()
  }
  let decoded = @core.decode_with_key(token, key) catch { _ => panic() }
  assert_eq(decoded.header().algorithm().name(), "HS256")
  assert_true(decoded.payload().get("iss") == Some(Json::string("joe")))
  assert_true(
    decoded.payload().get("http://example.com/is_root") ==
    Some(Json::boolean(true)),
  )
  match decoded.payload().get("exp") {
    Some(Number(exp, ..)) => assert_true(exp == 1300819380.0)
    _ => panic()
  }
}
