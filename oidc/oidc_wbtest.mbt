///|
/// RSA key fixture shared by the OIDC tests: the PKCS#8 form of the key whose
/// public half is exported below as a JWK.
const TEST_PRIVATE_PEM : String =
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
/// JWK members of the public half of `TEST_PRIVATE_PEM`.
const TEST_MODULUS : String = "qcmrp-2H3lKzToMRhG4dcsgKjbRpIva3IEXJlzGvFPF1YGP-F2BKgSQoTC2e0FueDbtWbPP6NCsa0dQ7IVbZ8-GpJLJhJmhhgrI1485GH-NxaDn8NFokokfmdob6FB_yrJO9Pc4DRzwdQNOkQqhEcvqcY8LWqeiyqQYRC2CEI082rGWRUXZRuC-d1Ws4-FlEqWrES_jM_mxg3YnYOI-bC1oWnD1V9mWONGFuc6RyUnFyCOH07XyKte9yhbcKm8VNJoZGAQn-QyYrdG54_sLjBkG3iq6yZkrN1ERuMI1aycfizuat9PNhDs4HzTQRACr82bX06FKn4kWXN4w-vtRk8Q"

///|
const TEST_KID : String = "rsa-1"

///|
const TEST_ISSUER : String = "https://auth.example.com"

///|
const TEST_AUDIENCE : String = "client-1"

///|
const TEST_NOW : Int64 = 1700000000

///|
fn test_jwks() -> Jwks {
  let json = @json.parse(
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"" +
    TEST_KID +
    "\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"" +
    TEST_MODULUS +
    "\",\"e\":\"AAEAAQ\"}]}",
  ) catch {
    _ => panic()
  }
  Jwks::from_json(json) catch {
    _ => panic()
  }
}

///|
fn test_policy() -> IdTokenValidation {
  IdTokenValidation::new(TEST_ISSUER, TEST_AUDIENCE, TEST_NOW) catch {
    _ => panic()
  }
}

///|
fn sign_id_token(claims : Array[(String, Json)], kid : String?) -> String {
  let payload = @core.Payload::new()
  for pair in claims {
    payload.set(pair.0, pair.1)
  }
  let header = match kid {
    Some(kid) => @core.Header::new(@core.RS256).with_kid(kid)
    None => @core.Header::new(@core.RS256)
  }
  @core.encode_rs256_with_header(payload, header, TEST_PRIVATE_PEM) catch {
    _ => panic()
  }
}

///|
fn base_claims() -> Array[(String, Json)] {
  [
    ("iss", Json::string(TEST_ISSUER)),
    ("aud", Json::string(TEST_AUDIENCE)),
    ("sub", Json::string("user-42")),
    ("iat", Json::number(1700000000.0)),
    ("exp", Json::number(1700000600.0)),
    ("nonce", Json::string("nonce-1")),
  ]
}

///|
test "oidc: discovery url normalizes trailing slashes" {
  assert_eq(
    ProviderMetadata::discovery_url("https://auth.example.com") catch {
      _ => panic()
    },
    "https://auth.example.com/.well-known/openid-configuration",
  )
  assert_eq(
    ProviderMetadata::discovery_url("https://auth.example.com///") catch {
      _ => panic()
    },
    "https://auth.example.com/.well-known/openid-configuration",
  )
}

///|
test "oidc: empty issuer is rejected when building a discovery url" {
  let rejected = try {
    ignore(ProviderMetadata::discovery_url("  "))
    false
  } catch {
    InvalidConfiguration(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: discovery document exposes the endpoints moonjwt needs" {
  let text =
    #|{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token","jwks_uri":"https://auth.example.com/jwks","userinfo_endpoint":"https://auth.example.com/userinfo","scopes_supported":["openid","profile"],"response_types_supported":["code"],"id_token_signing_alg_values_supported":["RS256"]}
  let json = @json.parse(text) catch { _ => panic() }
  let metadata = ProviderMetadata::from_json(json) catch { _ => panic() }
  assert_eq(metadata.issuer(), TEST_ISSUER)
  assert_eq(metadata.token_endpoint(), "https://auth.example.com/token")
  assert_eq(metadata.jwks_uri(), "https://auth.example.com/jwks")
  assert_eq(
    metadata.userinfo_endpoint(),
    Some("https://auth.example.com/userinfo"),
  )
  assert_eq(metadata.scopes_supported(), ["openid", "profile"])
  assert_eq(metadata.signing_algorithms(), ["RS256"])
}

///|
test "oidc: discovery document without jwks_uri is rejected" {
  let text =
    #|{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token"}
  let json = @json.parse(text) catch { _ => panic() }
  let rejected = try {
    ignore(ProviderMetadata::from_json(json))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: jwks exposes rsa keys and their modulus" {
  let keys = test_jwks()
  assert_eq(keys.length(), 1)
  let key = keys.key_by_id(TEST_KID)
  assert_true(key is Some(_))
  let key = match key {
    Some(key) => key
    None => panic()
  }
  assert_eq(key.key_id(), Some(TEST_KID))
  assert_eq(key.algorithm(), Some("RS256"))
  assert_true(key.modulus().length() > 0)
}

///|
test "oidc: jwks rejects unsupported key types" {
  let text =
    #|{"keys":[{"kty":"EC","kid":"ec-1","crv":"P-256"}]}
  let json = @json.parse(text) catch { _ => panic() }
  let rejected = try {
    ignore(Jwks::from_json(json))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: valid id token verifies against the jwks" {
  let token = sign_id_token(base_claims(), Some(TEST_KID))
  let policy = test_policy().with_nonce("nonce-1") catch { _ => panic() }
  let validated = validate_id_token(token, test_jwks(), policy) catch {
    _ => panic()
  }
  assert_eq(validated.subject(), "user-42")
  let issuer = match validated.claim("iss") {
    Some(String(value)) => value
    _ => panic()
  }
  assert_eq(issuer, TEST_ISSUER)
}

///|
test "oidc: id token with the wrong issuer is rejected" {
  let claims = base_claims()
  claims[0] = ("iss", Json::string("https://evil.example.com"))
  let token = sign_id_token(claims, Some(TEST_KID))
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), test_policy()))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: expired id token is rejected but clock skew can allow it" {
  let claims = base_claims()
  claims[4] = ("exp", Json::number(1699999999.0))
  let token = sign_id_token(claims, Some(TEST_KID))
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), test_policy()))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
  let tolerant = test_policy().with_clock_skew(60) catch { _ => panic() }
  let validated = validate_id_token(token, test_jwks(), tolerant) catch {
    _ => panic()
  }
  assert_eq(validated.subject(), "user-42")
}

///|
test "oidc: nonce mismatch is rejected" {
  let token = sign_id_token(base_claims(), Some(TEST_KID))
  let policy = test_policy().with_nonce("nonce-2") catch { _ => panic() }
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), policy))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: unknown kid is rejected" {
  let token = sign_id_token(base_claims(), Some("rsa-unknown"))
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), test_policy()))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: token without kid uses the single available key" {
  let token = sign_id_token(base_claims(), None)
  let validated = validate_id_token(token, test_jwks(), test_policy()) catch {
    _ => panic()
  }
  assert_eq(validated.subject(), "user-42")
}

///|
test "oidc: hs256 token cannot pass rsa verification" {
  let payload = @core.Payload::new()
  payload.set("iss", Json::string(TEST_ISSUER))
  let token = @core.encode_with_key(payload, b"not-the-signing-key") catch {
    _ => panic()
  }
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), test_policy()))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oidc: several audiences require a matching azp" {
  let claims = base_claims()
  claims[1] = (
    "aud",
    Json::array([Json::string(TEST_AUDIENCE), Json::string("other-client")]),
  )
  let token = sign_id_token(claims, Some(TEST_KID))
  let rejected = try {
    ignore(validate_id_token(token, test_jwks(), test_policy()))
    false
  } catch {
    InvalidIdToken(_) => true
    _ => false
  }
  assert_true(rejected)
  let with_azp = base_claims()
  with_azp[1] = (
    "aud",
    Json::array([Json::string(TEST_AUDIENCE), Json::string("other-client")]),
  )
  with_azp.push(("azp", Json::string(TEST_AUDIENCE)))
  let token = sign_id_token(with_azp, Some(TEST_KID))
  let validated = validate_id_token(token, test_jwks(), test_policy()) catch {
    _ => panic()
  }
  assert_eq(validated.subject(), "user-42")
}
