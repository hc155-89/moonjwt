///|
fn parse_json(text : String) -> Json {
  @json.parse(text) catch {
    _ => panic()
  }
}

///|
fn header_is_rejected(json : Json) -> Bool {
  try {
    ignore(Header::from_json(json))
    false
  } catch {
    _ => true
  }
}

///|
test "header round trip" {
  let header = Header::new(RS256).with_kid("2026-10")
  let decoded = Header::from_json(header.to_json()) catch { _ => panic() }
  assert_eq(decoded.alg.name(), "RS256")
  assert_eq(decoded.typ, "JWT")
  assert_true(decoded.kid == Some("2026-10"))
}

///|
test "header defaults typ to JWT" {
  let decoded = Header::from_json(parse_json("{\"alg\":\"HS256\"}")) catch {
    _ => panic()
  }
  assert_eq(decoded.alg.name(), "HS256")
  assert_eq(decoded.typ, "JWT")
  assert_true(decoded.kid == None)
}

///|
test "header rejects unsupported and malformed values" {
  assert_true(header_is_rejected(parse_json("{\"alg\":\"none\"}")))
  assert_true(header_is_rejected(parse_json("{\"alg\":\"ES256\"}")))
  assert_true(header_is_rejected(parse_json("{}")))
  assert_true(header_is_rejected(parse_json("{\"alg\":42}")))
  assert_true(header_is_rejected(parse_json("{\"alg\":\"HS256\",\"kid\":7}")))
  assert_true(header_is_rejected(parse_json("[]")))
}

///|
test "payload supports arbitrary claims" {
  let payload = Payload::new()
  payload.set("sub", Json::string("alice"))
  payload.set("admin", Json::boolean(true))
  payload.set(
    "roles",
    Json::array([Json::string("user"), Json::string("admin")]),
  )
  assert_eq(payload.length(), 3)
  assert_true(payload.contains("sub"))
  assert_true(payload.get("sub") == Some(Json::string("alice")))

  let decoded = Payload::from_json(payload.to_json()) catch { _ => panic() }
  assert_eq(decoded.length(), 3)
  assert_true(decoded.get("admin") == Some(Json::boolean(true)))
  assert_true(
    decoded.get("roles") ==
    Some(Json::array([Json::string("user"), Json::string("admin")])),
  )
}

///|
test "payload set replaces an existing claim" {
  let payload = Payload::new()
  payload.set("exp", Json::number(100.0))
  payload.set("exp", Json::number(200.0))
  assert_eq(payload.length(), 1)
  assert_true(payload.get("exp") == Some(Json::number(200.0)))
}

///|
test "payload rejects non-object JSON" {
  let rejected = try {
    ignore(Payload::from_json(parse_json("[]")))
    false
  } catch {
    InvalidJson(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "rfc 7519 example header decodes" {
  let text = decode_base64url_text("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") catch {
    _ => panic()
  }
  let header = Header::from_json(parse_json(text)) catch { _ => panic() }
  assert_eq(header.alg.name(), "HS256")
  assert_eq(header.typ, "JWT")
}
