///|
/// RSA fixture used to sign the ID tokens in this flow. It is the same demo key
/// as the CLI and is never a production secret.
const FLOW_PRIVATE_PEM : String =
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
const FLOW_JWKS : String = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"flow-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"qcmrp-2H3lKzToMRhG4dcsgKjbRpIva3IEXJlzGvFPF1YGP-F2BKgSQoTC2e0FueDbtWbPP6NCsa0dQ7IVbZ8-GpJLJhJmhhgrI1485GH-NxaDn8NFokokfmdob6FB_yrJO9Pc4DRzwdQNOkQqhEcvqcY8LWqeiyqQYRC2CEI082rGWRUXZRuC-d1Ws4-FlEqWrES_jM_mxg3YnYOI-bC1oWnD1V9mWONGFuc6RyUnFyCOH07XyKte9yhbcKm8VNJoZGAQn-QyYrdG54_sLjBkG3iq6yZkrN1ERuMI1aycfizuat9PNhDs4HzTQRACr82bX06FKn4kWXN4w-vtRk8Q\",\"e\":\"AAEAAQ\"}]}"

///|
const FLOW_ISSUER : String = "https://auth.example.com"

///|
const FLOW_CLIENT : String = "client-1"

///|
const FLOW_NONCE : String = "nonce-abc"

///|
fn flow_config() -> @oauth2.OAuth2Config {
  @oauth2.OAuth2Config::new(
    "https://auth.example.com/authorize",
    "https://auth.example.com/token",
    FLOW_CLIENT,
    "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
}

///|
fn flow_pkce() -> @oauth2.Pkce {
  @oauth2.Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") catch {
    _ => panic()
  }
}

///|
fn flow_id_token(nonce : String) -> String {
  let payload = @core.Payload::new()
  payload.set("iss", Json::string(FLOW_ISSUER))
  payload.set("aud", Json::string(FLOW_CLIENT))
  payload.set("sub", Json::string("user-42"))
  payload.set("iat", Json::number(1700000000.0))
  payload.set("exp", Json::number(1700000600.0))
  payload.set("nonce", Json::string(nonce))
  let header = @core.Header::new(@core.RS256).with_kid("flow-key")
  @core.encode_rs256_with_header(payload, header, FLOW_PRIVATE_PEM) catch {
    _ => panic()
  }
}

///|
test "integration: authorization request and token exchange agree on pkce" {
  let config = flow_config()
  let pkce = flow_pkce()
  let options = @oauth2.AuthCodeOptions::new("state-123").with_nonce(FLOW_NONCE)
  let options = options.with_pkce(pkce)
  let url = config.authorization_url(options)
  assert_true(url.contains("response_type=code"))
  assert_true(url.contains("code_challenge_method=S256"))
  assert_true(url.contains("nonce=" + FLOW_NONCE))
  let request = config.authorization_code_request("code-1", pkce~) catch {
    _ => panic()
  }
  assert_true(request.body().contains("grant_type=authorization_code"))
  assert_true(request.body().contains("code_verifier=" + pkce.verifier()))
}

///|
test "integration: token response carries a verifiable id token" {
  let token_json = @json.parse(
    "{\"access_token\":\"access-1\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"refresh-1\",\"id_token\":\"" +
    flow_id_token(FLOW_NONCE) +
    "\"}",
  ) catch {
    _ => panic()
  }
  let token = @oauth2.Token::from_json(token_json) catch { _ => panic() }
  assert_eq(token.token_type(), "Bearer")
  assert_eq(token.expires_in(), Some(3600L))
  let id_token = match token.id_token() {
    Some(value) => value
    None => panic()
  }
  let keys = @oidc.Jwks::from_json(
    @json.parse(FLOW_JWKS) catch {
      _ => panic()
    },
  ) catch {
    _ => panic()
  }
  let policy = @oidc.IdTokenValidation::new(
    FLOW_ISSUER,
    FLOW_CLIENT,
    1700000001,
  ).with_nonce(FLOW_NONCE)
  let validated = @oidc.validate_id_token(id_token, keys, policy) catch {
    _ => panic()
  }
  assert_eq(validated.subject(), "user-42")
}

///|
test "integration: token response with a replayed nonce is rejected" {
  let token_json = @json.parse(
    "{\"access_token\":\"access-1\",\"token_type\":\"Bearer\",\"id_token\":\"" +
    flow_id_token("nonce-from-another-session") +
    "\"}",
  ) catch {
    _ => panic()
  }
  let token = @oauth2.Token::from_json(token_json) catch { _ => panic() }
  let id_token = match token.id_token() {
    Some(value) => value
    None => panic()
  }
  let keys = @oidc.Jwks::from_json(
    @json.parse(FLOW_JWKS) catch {
      _ => panic()
    },
  ) catch {
    _ => panic()
  }
  let policy = @oidc.IdTokenValidation::new(
    FLOW_ISSUER,
    FLOW_CLIENT,
    1700000001,
  ).with_nonce(FLOW_NONCE)
  let rejected = try {
    ignore(@oidc.validate_id_token(id_token, keys, policy))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}
