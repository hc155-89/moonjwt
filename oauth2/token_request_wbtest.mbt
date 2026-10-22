///|
fn test_config() -> OAuth2Config {
  OAuth2Config::new(
    "https://auth.example.com/authorize", "https://auth.example.com/token", "client-1",
    "https://app.example.com/callback",
  ) catch {
    _ => panic()
  }
}

///|
test "token request: public client sends client_id in the body" {
  let config = test_config()
  let pkce = Pkce::from_verifier(RFC7636_VERIFIER) catch { _ => panic() }
  let request = config.authorization_code_request("code-1", pkce~) catch {
    _ => panic()
  }
  assert_eq(request.http_method(), "POST")
  assert_eq(request.url(), "https://auth.example.com/token")
  assert_eq(
    request.header("Content-Type"),
    Some("application/x-www-form-urlencoded"),
  )
  assert_eq(request.header("Accept"), Some("application/json"))
  assert_eq(request.header("Authorization"), None)
  assert_eq(
    request.body(),
    "grant_type=authorization_code&code=code-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier=" +
    RFC7636_VERIFIER +
    "&client_id=client-1",
  )
}

///|
test "token request: confidential client uses http basic" {
  let config = test_config()
  let config = config.with_client_secret("s3cret") catch { _ => panic() }
  let request = config.authorization_code_request("code-1") catch {
    _ => panic()
  }
  assert_eq(request.header("Authorization"), Some("Basic Y2xpZW50LTE6czNjcmV0"))
  assert_true(!request.body().contains("client_id"))
  assert_true(!request.body().contains("client_secret"))
  assert_eq(
    request.body(),
    "grant_type=authorization_code&code=code-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
  )
}

///|
test "token request: empty authorization code is rejected" {
  let config = test_config()
  let rejected = try {
    ignore(config.authorization_code_request(" "))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "token request: refresh token grant" {
  let config = test_config()
  let request = config.refresh_token_request("refresh-1") catch { _ => panic() }
  assert_eq(
    request.body(),
    "grant_type=refresh_token&refresh_token=refresh-1&client_id=client-1",
  )
  let rejected = try {
    ignore(config.refresh_token_request(""))
    false
  } catch {
    InvalidRequest(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "token request: client credentials grant encodes scopes as a form" {
  let config = test_config()
  let config = config.with_client_secret("s3cret") catch { _ => panic() }
  let config = config.with_scopes(["openid", "profile"])
  let request = config.client_credentials_request() catch { _ => panic() }
  assert_eq(
    request.body(),
    "grant_type=client_credentials&scope=openid+profile",
  )
  assert_eq(request.header("Authorization"), Some("Basic Y2xpZW50LTE6czNjcmV0"))
}

///|
test "token request: client credentials requires a confidential client" {
  let config = test_config()
  let rejected = try {
    ignore(config.client_credentials_request())
    false
  } catch {
    InvalidConfiguration(_) => true
    _ => false
  }
  assert_true(rejected)
}
