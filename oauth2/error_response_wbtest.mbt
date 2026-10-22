///|
test "oauth2 error response: parses a registered error code" {
  let json = @json.parse(
    "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\",\"error_uri\":\"https://auth.example.com/errors/invalid_grant\"}",
  ) catch {
    _ => panic()
  }
  let response = OAuth2ErrorResponse::from_json(json) catch { _ => panic() }
  assert_eq(response.error(), "invalid_grant")
  assert_eq(response.description(), Some("code expired"))
  assert_eq(
    response.uri(),
    Some("https://auth.example.com/errors/invalid_grant"),
  )
  assert_true(response.requires_new_grant())
}

///|
test "oauth2 error response: an error without a code is rejected" {
  let json = @json.parse("{\"error_description\":\"missing code\"}") catch {
    _ => panic()
  }
  let rejected = try {
    ignore(OAuth2ErrorResponse::from_json(json))
    false
  } catch {
    InvalidResponse(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "oauth2 error response: unrelated codes do not require a new grant" {
  let json = @json.parse("{\"error\":\"temporarily_unavailable\"}") catch {
    _ => panic()
  }
  let response = OAuth2ErrorResponse::from_json(json) catch { _ => panic() }
  assert_eq(response.description(), None)
  assert_false(response.requires_new_grant())
}
