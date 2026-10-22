///|
test "public api: authorization url with pkce" {
  let config = @oauth2.OAuth2Config::new(
    "https://auth.example.com/authorize", "https://auth.example.com/token", "demo-client",
    "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
  let config = config.with_scopes(["openid", "profile"])
  let pkce = @oauth2.Pkce::from_entropy(b"0123456789abcdef0123456789abcdef") catch {
    _ => panic()
  }
  let options = @oauth2.AuthCodeOptions::new("state-42") catch { _ => panic() }
  let options = options.with_pkce(pkce)
  let url = config.authorization_url(options)
  assert_true(url.contains("client_id=demo-client"))
  assert_true(url.contains("scope=openid%20profile"))
  assert_true(url.contains("state=state-42"))
  assert_true(url.contains("code_challenge=" + pkce.challenge()))
  assert_true(url.contains("code_challenge_method=S256"))
}

///|
test "public api: token response" {
  let object : Map[String, Json] = Map([])
  object.set("access_token", Json::string("access-1"))
  object.set("token_type", Json::string("Bearer"))
  object.set("expires_in", Json::number(3600.0))
  let token = @oauth2.Token::from_json(Json::object(object)) catch {
    _ => panic()
  }
  assert_eq(token.access_token(), "access-1")
  assert_eq(token.token_type(), "Bearer")
  assert_eq(token.expires_in(), Some(3600L))
  assert_eq(token.refresh_token(), None)
}

///|
test "public api: grant types" {
  let grants = @oauth2.GrantType::all()
  assert_eq(grants.length(), 3)
  assert_eq(@oauth2.GrantType::AuthorizationCode.value(), "authorization_code")
  assert_eq(@oauth2.GrantType::RefreshToken.value(), "refresh_token")
}
