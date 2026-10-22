///|
/// Demo PKCS#8 key. It exists only so the CLI can show an RS256 round trip and
/// is explicitly not a secret to reuse anywhere.
const DEMO_PRIVATE_PEM : String =
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
/// Demo JWKS matching `DEMO_PRIVATE_PEM`.
const DEMO_JWKS : String = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"demo-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"qcmrp-2H3lKzToMRhG4dcsgKjbRpIva3IEXJlzGvFPF1YGP-F2BKgSQoTC2e0FueDbtWbPP6NCsa0dQ7IVbZ8-GpJLJhJmhhgrI1485GH-NxaDn8NFokokfmdob6FB_yrJO9Pc4DRzwdQNOkQqhEcvqcY8LWqeiyqQYRC2CEI082rGWRUXZRuC-d1Ws4-FlEqWrES_jM_mxg3YnYOI-bC1oWnD1V9mWONGFuc6RyUnFyCOH07XyKte9yhbcKm8VNJoZGAQn-QyYrdG54_sLjBkG3iq6yZkrN1ERuMI1aycfizuat9PNhDs4HzTQRACr82bX06FKn4kWXN4w-vtRk8Q\",\"e\":\"AAEAAQ\"}]}"

///|
/// Demo discovery document served by the fictional provider.
const DEMO_DISCOVERY : String = "{\"issuer\":\"https://auth.example.com\",\"authorization_endpoint\":\"https://auth.example.com/authorize\",\"token_endpoint\":\"https://auth.example.com/token\",\"jwks_uri\":\"https://auth.example.com/jwks\",\"response_types_supported\":[\"code\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}"

///|
fn demo_hs256() -> Unit raise @core.JwtError {
  println("1. HS256 sign and verify")
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("user-42"))
  payload.set("role", Json::string("reader"))
  let token = @core.encode(payload, "demo-secret")
  println("   token: " + token)
  let decoded = @core.decode(token, "demo-secret")
  let subject = match decoded.payload().get("sub") {
    Some(String(value)) => value
    _ => "<missing>"
  }
  println("   verified subject: " + subject)
  let rejected = try {
    ignore(@core.decode(token, "wrong-secret"))
    false
  } catch {
    _ => true
  }
  println("   wrong secret rejected: " + rejected.to_string())
}

///|
fn demo_oauth2() -> Unit raise @oauth2.OAuth2Error {
  println("")
  println("2. OAuth2 authorization code request with PKCE")
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let pkce = @oauth2.Pkce::from_verifier(verifier)
  let config = @oauth2.OAuth2Config::new(
    "https://auth.example.com/authorize", "https://auth.example.com/token", "client-1",
    "https://app.example.com/callback",
  ).with_scopes(["openid", "profile"])
  let base_options = @oauth2.AuthCodeOptions::new("state-123")
  let options = base_options.with_nonce("nonce-abc").with_pkce(pkce)
  println("   authorization url: " + config.authorization_url(options))
  let request = config.authorization_code_request("demo-code", pkce~)
  println("   token method: " + request.http_method())
  println("   token body: " + request.body())
}

///|
fn demo_oidc() -> Unit raise @oidc.OidcError {
  println("")
  println("3. OIDC discovery and ID token validation")
  let metadata = @oidc.ProviderMetadata::from_json(
    @json.parse(DEMO_DISCOVERY) catch {
      _ => raise @oidc.InvalidResponse("demo discovery document is not JSON")
    },
  ) catch {
    _ => raise @oidc.InvalidResponse("demo discovery document is invalid")
  }
  println("   issuer: " + metadata.issuer())
  println("   jwks uri: " + metadata.jwks_uri())
  let keys = @oidc.Jwks::from_json(
    @json.parse(DEMO_JWKS) catch {
      _ => raise @oidc.InvalidResponse("demo JWKS is not JSON")
    },
  ) catch {
    _ => raise @oidc.InvalidResponse("demo JWKS is invalid")
  }
  let payload = @core.Payload::new()
  payload.set("iss", Json::string(metadata.issuer()))
  payload.set("aud", Json::string("client-1"))
  payload.set("sub", Json::string("user-42"))
  payload.set("iat", Json::number(1700000000.0))
  payload.set("exp", Json::number(1700000600.0))
  payload.set("nonce", Json::string("nonce-abc"))
  let header = @core.Header::new(@core.RS256).with_kid("demo-key")
  let token = @core.encode_rs256_with_header(payload, header, DEMO_PRIVATE_PEM) catch {
    _ => raise @oidc.InvalidResponse("could not sign the demo ID token")
  }
  let policy = @oidc.IdTokenValidation::new(
    metadata.issuer(),
    "client-1",
    1700000001,
  ).with_nonce("nonce-abc")
  let verified = @oidc.validate_id_token(token, keys, policy) catch {
    _ => raise @oidc.InvalidIdToken("demo ID token did not validate")
  }
  println("   verified subject: " + verified.subject())
  let audience = match verified.claim("aud") {
    Some(String(value)) => value
    _ => "<missing>"
  }
  println("   verified audience: " + audience)
}

///|
fn main {
  println("moonjwt 0.1.0 - pure MoonBit JWT + OAuth2/OIDC toolkit")
  println("")
  demo_hs256() catch {
    _ => println("   HS256 demo failed")
  }
  demo_oauth2() catch {
    _ => println("   OAuth2 demo failed")
  }
  demo_oidc() catch {
    _ => println("   OIDC demo failed")
  }
}
