///|
/// RFC 7636 Appendix B publishes this verifier/challenge pair.
const RFC7636_VERIFIER : String = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

///|
const RFC7636_CHALLENGE : String = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

///|
test "pkce: rfc 7636 appendix b vector" {
  assert_eq(code_challenge_s256(RFC7636_VERIFIER), RFC7636_CHALLENGE)
  let pkce = Pkce::from_verifier(RFC7636_VERIFIER) catch { _ => panic() }
  assert_eq(pkce.verifier(), RFC7636_VERIFIER)
  assert_eq(pkce.challenge(), RFC7636_CHALLENGE)
  assert_eq(pkce.transformation().value(), "S256")
}

///|
test "pkce: entropy produces a valid verifier" {
  let pkce = Pkce::from_entropy(b"0123456789abcdef0123456789abcdef") catch {
    _ => panic()
  }
  assert_eq(pkce.verifier().length(), 43)
  assert_eq(
    pkce.challenge(),
    code_challenge_s256(pkce.verifier()) catch {
      _ => panic()
    },
  )
}

///|
test "pkce: out-of-range entropy is rejected" {
  let short = try {
    ignore(Pkce::from_entropy(b"0123456789abcdef"))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  let long = try {
    ignore(Pkce::from_entropy(Bytes::make(97, b'\x00')))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  assert_true(short)
  assert_true(long)
}

///|
test "pkce: invalid verifiers are rejected" {
  let too_short = try {
    ignore(Pkce::from_verifier("abc"))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  let too_long = try {
    ignore(Pkce::from_verifier(String::make(129, 'a')))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  let bad_char = try {
    ignore(Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!"))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  assert_true(too_short)
  assert_true(too_long)
  assert_true(bad_char)
}

///|
test "url: percent encoding follows rfc 3986" {
  assert_eq(percent_encode("a b/c?d=e&f~_.-"), "a%20b%2Fc%3Fd%3De%26f~_.-")
  assert_eq(percent_encode("你好"), "%E4%BD%A0%E5%A5%BD")
  assert_eq(percent_encode("AZaz09"), "AZaz09")
}

///|
test "authorization url: complete request" {
  let config = OAuth2Config::new(
    "https://auth.example.com/authorize", "https://auth.example.com/token", "client-1",
    "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
  let pkce = Pkce::from_verifier(RFC7636_VERIFIER) catch { _ => panic() }
  let options = AuthCodeOptions::new("state-1") catch { _ => panic() }
  let options = options.with_scopes(["openid", "profile"])
  let options = options.with_pkce(pkce)
  let url = config.authorization_url(options)
  assert_eq(
    url,
    "https://auth.example.com/authorize?response_type=code&client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile&state=state-1&code_challenge=" +
    RFC7636_CHALLENGE +
    "&code_challenge_method=S256",
  )
}

///|
test "authorization url: nonce and custom parameters" {
  let config = OAuth2Config::new(
    "https://auth.example.com/authorize?tenant=t1", "https://auth.example.com/token",
    "client-1", "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
  let options = AuthCodeOptions::new("state-2") catch { _ => panic() }
  let options = options.with_nonce("nonce-2") catch { _ => panic() }
  let options = options.with_parameter("prompt", "consent") catch {
    _ => panic()
  }
  let url = config.authorization_url(options)
  assert_eq(
    url, "https://auth.example.com/authorize?tenant=t1&response_type=code&client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&state=state-2&nonce=nonce-2&prompt=consent",
  )
}

///|
test "authorization url: configured default scopes are used" {
  let config = OAuth2Config::new(
    "https://auth.example.com/authorize", "https://auth.example.com/token", "client-1",
    "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
  let config = config.with_scopes(["openid", "email"])
  let url = config.authorization_url(
    AuthCodeOptions::new("state-3") catch {
      _ => panic()
    },
  )
  assert_true(url.contains("scope=openid%20email"))
}

///|
test "configuration validation rejects empty fields" {
  let empty_client = try {
    ignore(
      OAuth2Config::new(
        "https://auth.example.com/authorize", "https://auth.example.com/token", " ",
        "https://app.example.com/callback",
      ),
    )
    false
  } catch {
    InvalidConfiguration(_) => true
    _ => false
  }
  let empty_state = try {
    ignore(AuthCodeOptions::new(""))
    false
  } catch {
    InvalidConfiguration(_) => true
    _ => false
  }
  assert_true(empty_client)
  assert_true(empty_state)
}

///|
test "auth code options reject reserved parameters" {
  let options = AuthCodeOptions::new("state") catch { _ => panic() }
  let rejected = try {
    ignore(options.with_parameter("redirect_uri", "https://evil.example.com"))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "token response parsing" {
  let object : Map[String, Json] = Map([])
  object.set("access_token", Json::string("access-1"))
  object.set("token_type", Json::string("Bearer"))
  object.set("expires_in", Json::number(3600.0))
  object.set("refresh_token", Json::string("refresh-1"))
  object.set("scope", Json::string("openid profile"))
  object.set("id_token", Json::string("id-1"))
  let token = Token::from_json(Json::object(object)) catch { _ => panic() }
  assert_eq(token.access_token(), "access-1")
  assert_eq(token.token_type(), "Bearer")
  assert_eq(token.expires_in(), Some(3600L))
  assert_eq(token.refresh_token(), Some("refresh-1"))
  assert_eq(token.scope(), Some("openid profile"))
  assert_eq(token.id_token(), Some("id-1"))
}

///|
test "token response requires access_token and token_type" {
  let object : Map[String, Json] = Map([])
  object.set("token_type", Json::string("Bearer"))
  let missing = try {
    ignore(Token::from_json(Json::object(object)))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  object.set("access_token", Json::string("access-1"))
  object.set("token_type", Json::null())
  let wrong_type = try {
    ignore(Token::from_json(Json::object(object)))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  assert_true(missing)
  assert_true(wrong_type)
}

///|
test "token response rejects fractional expiry" {
  let object : Map[String, Json] = Map([])
  object.set("access_token", Json::string("access-1"))
  object.set("token_type", Json::string("Bearer"))
  object.set("expires_in", Json::number(1.5))
  let rejected = try {
    ignore(Token::from_json(Json::object(object)))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  assert_true(rejected)
}
