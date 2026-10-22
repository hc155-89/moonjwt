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

///|
/// SPKI public key matching the RSA token below.
const RS256_SPKI_PEM : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqcmrp+2H3lKzToMRhG4d
  #|csgKjbRpIva3IEXJlzGvFPF1YGP+F2BKgSQoTC2e0FueDbtWbPP6NCsa0dQ7IVbZ
  #|8+GpJLJhJmhhgrI1485GH+NxaDn8NFokokfmdob6FB/yrJO9Pc4DRzwdQNOkQqhE
  #|cvqcY8LWqeiyqQYRC2CEI082rGWRUXZRuC+d1Ws4+FlEqWrES/jM/mxg3YnYOI+b
  #|C1oWnD1V9mWONGFuc6RyUnFyCOH07XyKte9yhbcKm8VNJoZGAQn+QyYrdG54/sLj
  #|BkG3iq6yZkrN1ERuMI1aycfizuat9PNhDs4HzTQRACr82bX06FKn4kWXN4w+vtRk
  #|8QIDAQAB
  #|-----END PUBLIC KEY-----

///|
/// PKCS#8 private key matching `RS256_SPKI_PEM`.
const RS256_PKCS8_PEM : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpyaun7YfeUrNO
  #|gxGEbh1yyAqNtGki9rcgRcmXMa8U8XVgY/4XYEqBJChMLZ7QW54Nu1Zs8/o0KxrR
  #|1DshVtnz4akksmEmaGGCsjXjzkYf43FoOfw0WiSiR+Z2hvoUH/Ksk709zgNHPB1A
  #|06RCqERy+pxjwtap6LKpBhELYIQjTzasZZFRdlG4L53Vazj4WUSpasRL+Mz+bGDd
  #|idg4j5sLWhacPVX2ZY40YW5zpHJScXII4fTtfIq173KFtwqbxU0mhkYBCf5DJit0
  #|bnj+wuMGQbeKrrJmSs3URG4wjVrJx+LO5q3082EOzgfNNBEAKvzZtfToUqfiRZc3
  #|jD6+1GTxAgMBAAECggEABs1LAK+95TS39Tm//mew61PDRHkJSzrKDFNvZ4y4gGTJ
  #|+IIZAFO9uF279Y1QUvWQp+ks5bGCgQuHCAfyFHxXv/L25T72MGU3HtbH3Of7HDTu
  #|6qeECI7h79RkkbQHmb3L6YkDqFG0BOsOGvY/muIF1/tdP4vjMKxfV/EjxqpnsMhf
  #|aPDZZO6tm/QNrdlpSXhAhClrNWW3idyEz4b9q/OM4eP6EG3Sn2zipQxf+LHK/s8z
  #|qOpF607DXjEykzOxQDrOhuUs2xSRZ6oZHVwj6NBBF+VvloRNdf4FWbmaizK/RYZv
  #|EQYtzHzFLxrTwwDbfinC6t083bOUn3umPsnnUBnV1wKBgQDWJ4m78K/P6i1XGOQG
  #|OYWJsWg3c6l1iqsdCU/CuQbaD//eCWdoCXIvqJ/ECKL5j6MMed1BpYQE1Bfd2AR2
  #|3xfW5tQk1FmTLVRPJQD+3fSweVUY7/we8Dxug/Kf1b9I3QxkJ2oi0NrYDZ5Wu5Vw
  #|n685KSaEHcWCXZQjf5FuwjwcvwKBgQDK9tEsOk1zQ3yh6c98La/NEH132bsj0MT0
  #|ELMRjgpztvda55QoNaPY0u70d2lxSrWVqoV43hxvwLuSGrspgz3LG4BtGzHCq8hT
  #|nKz5t9+1b8Ry7TKaQf14cjUEDPeosKYuUGPw0p+cqgP5PT3aV3z5sgH8nqFlYMjh
  #|ORxkogv6TwKBgGwPJUvFBiGma1xwfda6Payd7RVV8mMSJoePRETgMhnkStqR6jCv
  #|24M61esH5JyCouZPs5pFV1lMYAKb1pzYs2HHtbIjyFMgY1NQO7Fe8/H8NzlPFuvR
  #|kty9DbcjFtNAXtlGniKVOmgcbxIasyxSFwuDvSCbGSdP6skCvLKjpctnAoGARo3y
  #|PMuvrMfjBW3/4I0JNeHrm8Qml9a1AJrlhM65t2v9JK6oBCpRYMhCpNz13Jo58WMr
  #|rs6XWAnJqop8UXv7+SUASe1QKPoKU3Z9cvmGXM4TnlfyZUlXUY1x/Ix9czilLChp
  #|9YdiUNWROA0f+Uy8dxh4NFb4iANTEWgHBLyIKWUCgYAB67eghAxoYzTUFmZNhymI
  #|qYsCB4cWiGl/B33SnxHmJ+KHm+bIakCdgw2Oxi3QABt7bnDc2c/ZGf/rD96C6NoD
  #|OgVEkFLgt2dWdO/ccUGt6lFbSByOIEru4Y/dx/oGv1AVbwV/MxsFwsgeazUPmdA3
  #|2FU2nTjw73UbvaHudyDirg==
  #|-----END PRIVATE KEY-----

///|
/// Token signed by OpenSSL with `RS256_SPKI_PEM`'s private key.
const RS256_EXTERNAL_TOKEN : String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtb29uand0Iiwic3ViIjoicnMyNTYtdmVjdG9yIiwiYXVkIjoiZGVtbyJ9.M5srEBM5lmEiTAb9MsWdbbawWTC8YXUpFbeG0y9eJrt5NUwm2YtdcZ4GUIMIA5hluAeBMIQ4c9eHMRbmzrAgcC84GnK5bohvw6pCvWcMlpsgdw0SyxulAxfTlXIlIjHDjnWGADfXMFfg9OE854FjL0sGDsn7_LlxDsiouqKFVbi_xm0a3EEnKz9ebE4Ai2Or05aF8eFvSVWqIaWJGauPmPwhWiAyZhx08RFyLMACb8drCRRrGq81ly7HPUSEC9TNL8egmtlKMLSw-3E1jhTirjiBQE3zyNElct7Y4JYgH8PQrKnopEuLQgXtsNMexZmSxsJvWoaofP_ou2t3UAkQmQ"

///|
test "rs256: external openssl token verifies" {
  let decoded = @core.decode_rs256(RS256_EXTERNAL_TOKEN, RS256_SPKI_PEM) catch {
    _ => panic()
  }
  assert_eq(decoded.header().algorithm().name(), "RS256")
  assert_true(decoded.payload().get("iss") == Some(Json::string("moonjwt")))
  assert_true(
    decoded.payload().get("sub") == Some(Json::string("rs256-vector")),
  )
}

///|
test "rs256: sign and verify round trip with key id" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("alice"))
  let header = @core.Header::new(@core.RS256).with_kid("rsa-2026")
  let token = @core.encode_rs256_with_header(payload, header, RS256_PKCS8_PEM) catch {
    _ => panic()
  }
  let decoded = @core.decode_rs256(token, RS256_SPKI_PEM) catch { _ => panic() }
  assert_eq(decoded.header().algorithm().name(), "RS256")
  assert_true(decoded.header().key_id() == Some("rsa-2026"))
  assert_true(decoded.payload().get("sub") == Some(Json::string("alice")))
}

///|
test "rs256: tampered payload is rejected" {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("alice"))
  let token = @core.encode_rs256(payload, RS256_PKCS8_PEM) catch {
    _ => panic()
  }
  let segments = Array::from_iter(token.split("."))
  let forged_payload = @core.encode_base64url_text("{\"sub\":\"mallory\"}")
  let tampered = segments[0].to_owned() +
    "." +
    forged_payload +
    "." +
    segments[2].to_owned()
  let rejected = try {
    ignore(@core.decode_rs256(tampered, RS256_SPKI_PEM))
    false
  } catch {
    @core.InvalidSignature => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "algorithm confusion is rejected in both directions" {
  let hs_token = @core.encode(@core.Payload::new(), "secret") catch {
    _ => panic()
  }
  let rs_token_with_hs = try {
    ignore(@core.decode_rs256(hs_token, RS256_SPKI_PEM))
    false
  } catch {
    @core.UnsupportedAlgorithm(_) => true
    _ => false
  }
  let hs_with_rs = try {
    ignore(@core.decode(RS256_EXTERNAL_TOKEN, "secret"))
    false
  } catch {
    @core.UnsupportedAlgorithm(_) => true
    _ => false
  }
  assert_true(rs_token_with_hs)
  assert_true(hs_with_rs)
}

///|
test "rs256: encoding rejects an hs256 header" {
  let header = @core.Header::new(@core.HS256)
  let rejected = try {
    ignore(
      @core.encode_rs256_with_header(
        @core.Payload::new(),
        header,
        RS256_PKCS8_PEM,
      ),
    )
    false
  } catch {
    @core.UnsupportedAlgorithm(_) => true
    _ => false
  }
  assert_true(rejected)
}
