# moonjwt

**纯 MoonBit 实现的 JWT（RFC 7519）与 OAuth2 / OIDC 客户端基础库，零 FFI 依赖。**

一份源码面向 WebAssembly 编译，可在 WASI 沙箱内不请求任何宿主能力地完成 JWT
签发与校验、OAuth2 授权码流程的请求构造、OIDC Discovery 解析与 ID Token 验证；
对外收敛为 `core` / `oauth2` / `oidc` 三个包。

[![CI](https://github.com/hc155-89/moonjwt/actions/workflows/ci.yml/badge.svg)](https://github.com/hc155-89/moonjwt/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

---

## 一、项目基本信息

| 项目 | 内容 |
| --- | --- |
| 项目名称 | moonjwt |
| 参赛者 | 黄才 |
| 联系方式 | 1558929138@qq.com |
| GitHub 仓库 | <https://github.com/hc155-89/moonjwt> |
| 项目方向 | 身份认证基础库 / JWT、OAuth2、OpenID Connect |
| 是否为移植项目 | 否，原创项目 |
| 模块名 | `hc155-89/moonjwt`（遵循 mooncakes.io 的 `<author>/<module>` 命名规范） |
| 代码规模 | 2545 行库源码 + 1530 行测试，32 个 `.mbt` 文件，合计 4075 行 |
| 测试状态 | `moon test --target wasm` 全部通过（83 个用例，0 失败）；行覆盖率 833 / 1019 |
| 构建状态 | `moon check --target wasm --deny-warn` 零错误、零告警；CLI 可执行文件链接成功 |
| 开源许可证 | Apache-2.0 |

## 二、项目简介

身份认证是每个服务端应用都无法回避的基础设施，而 JSON Web Token 是其中事实上的
通行证格式：登录态、服务间调用、单点登录、开放平台授权，最终都以一段签名字符串
在系统之间流转。围绕 JWT 的 OAuth2 授权码流程与 OIDC 身份层，则决定了"用户如何
证明自己是谁"。

**MoonBit 生态目前缺少这一环。** 现成的 JWT / OAuth2 实现要么来自其他语言的
C / Rust 绑定，要么依赖宿主运行时自带的安全库与网络栈；前者破坏 WASM 沙箱的
可移植性，后者在 WASI 中根本不可用。moonjwt 用于补齐这块空白：Base64URL、
SHA-256、HMAC-SHA256、RSA PKCS#1 v1.5 签名校验、PEM / DER 密钥解析、JWK 公钥
还原、JWT 编解码、OAuth2 表单请求与 PKCE、OIDC Discovery 与 ID Token 校验，
全部由 MoonBit 自身完成。

**与现有能力的本质区别**

- 与 FFI 封装相比：不做任何 C / Rust 绑定，不链接 OpenSSL，也不调用宿主加密 API；
  相同源码在 WebAssembly 后端通过检查与测试，可直接放进 WASI 沙箱运行。
- 与"示例级 JWT 代码"相比：拒绝 `alg: none`、双向拒绝算法混淆、签名使用常量时间
  比较、先验签再解析 payload，安全策略写在代码路径里而不是文档提醒里。
- 与"只封装 HTTP"的 SDK 相比：本库不内置 HTTP 客户端，而是产出可直接发送的
  请求对象（URL、方法、头部、表单体），把网络与随机源交给调用方，保持零宿主依赖。

## 三、典型使用场景

三个场景都由 [cmd/main/main.mbt](./cmd/main/main.mbt) 用同一份代码真实跑通，
输入是仓库内嵌的字节流与演示密钥，不读取文件、不请求宿主能力。

### 3.1 签发并校验 HS256 访问令牌

- **输入**：`sub=user-42`、`role=reader` 的 claims 与 UTF-8 密钥 `demo-secret`
- **调用**：`@core.encode(payload, secret)` → `@core.decode(token, secret)`
- **输出**：`verified subject: user-42`；使用错误密钥时 `wrong secret rejected: true`
- **要点**：签名段经 Base64URL 解码后与重算 HMAC 做常量时间比较，
  校验失败不会返回任何 claim。

### 3.2 构造带 PKCE 的 OAuth2 授权码请求

- **输入**：客户端 `client-1`、回调地址、RFC 7636 官方示例 verifier、
  `state` 与 `nonce`
- **调用**：`@oauth2.OAuth2Config::authorization_url(options)`
  → `authorization_code_request(code, pkce~)`
- **输出**：完整授权 URL（含 `code_challenge_method=S256`）与 token 端点的
  `application/x-www-form-urlencoded` 请求体（含 `code_verifier`）
- **要点**：URL 查询空格编码为 `%20`，表单体空格编码为 `+`，
  分别符合 RFC 3986 与 RFC 6749 Appendix B。

### 3.3 验证 OIDC ID Token

- **输入**：内嵌 Discovery 文档、内嵌 JWKS（RSA 公钥 `n` / `e`）、
  由演示私钥签发的 ID Token
- **调用**：`@oidc.ProviderMetadata::from_json`
  → `@oidc.Jwks::from_json` → `@oidc.validate_id_token(token, keys, policy)`
- **输出**：`verified subject: user-42`、`verified audience: client-1`
- **要点**：按 `kid` 选键、用 JWK 组件还原公钥、先验签再校验
  `iss` / `aud` / `azp` / `exp` / `iat` / `nbf` / `nonce`。

在仓库根目录运行（`--target wasm` 使用 MoonBit 自带的 WASI 运行时）：

```bash
moon run cmd/main --target wasm
```

实际输出：

```text
moonjwt 0.1.0 - pure MoonBit JWT + OAuth2/OIDC toolkit

1. HS256 sign and verify
   token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6InJlYWRlciJ9.4N03Ms3tUVVz7QgLyeFMkjhCTMl0KvpxXFFRy3GJtMM
   verified subject: user-42
   wrong secret rejected: true

2. OAuth2 authorization code request with PKCE
   authorization url: https://auth.example.com/authorize?response_type=code&client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile&state=state-123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&nonce=nonce-abc
   token method: POST
   token body: grant_type=authorization_code&code=demo-code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&client_id=client-1

3. OIDC discovery and ID token validation
   issuer: https://auth.example.com
   jwks uri: https://auth.example.com/jwks
   verified subject: user-42
   verified audience: client-1
```

> 示例中的 RSA 私钥仅用于演示签名链路，**不是可复用的密钥**。

## 四、核心功能范围

- **JWT 签发与校验**：Header / Payload 的 JSON 序列化、Base64URL 紧凑序列化、
  HS256 与 RS256 两种算法。
- **纯 MoonBit 加密原语**：SHA-256（FIPS 180-4）、HMAC-SHA256（RFC 2104）、
  Base64URL 严格编解码（RFC 4648 §5，拒绝非法填充与非字母表字符）。
- **RSA 支持**：PKCS#1 v1.5 + SHA-256 签名与校验（RFC 8017 §8.2）；
  PEM 解析覆盖 PKCS#1 / PKCS#8 私钥与 PKCS#1 / SPKI 公钥；
  另支持从 JWK 的 `n` / `e` 组件直接构造公钥。
- **注册声明支持**：`Header` 保留 `alg` / `typ` / `kid`，`Payload` 不限制 claim
  名称，业务自定义声明可原样往返。
- **算法安全策略**：`alg` 必须属于已实现集合，`none` 与未知算法直接拒绝；
  HS256 与 RS256 双向拒绝混淆；签名比较为常量时间；payload 仅在验签通过后解析。
- **OAuth2 授权码流程**：固定顺序生成授权 URL，`state` 强制非空，
  支持 `nonce`、scope 覆盖与自定义扩展参数（保留参数禁止覆盖）。
- **PKCE（RFC 7636）**：S256 challenge 计算；verifier 规则校验（长度、字符集）；
  支持外部注入 32–96 字节熵派生 verifier，避免依赖不可靠的宿主机随机源。
- **Token Exchange 请求构造**：`authorization_code` / `refresh_token` /
  `client_credentials` 三种 grant 的 `application/x-www-form-urlencoded` 请求；
  机密客户端使用 HTTP Basic（RFC 6749 §2.3.1），公共客户端在请求体携带 `client_id`。
- **Token 响应解析**：`access_token` / `token_type` 必填，`expires_in` 必须为
  非负整数秒；可选 `refresh_token`、`scope`、`id_token`。
- **OAuth2 错误响应解析**：按 RFC 6749 §5.2 解析 `error` / `error_description` /
  `error_uri`，并标识 `invalid_grant` 需要重新获取授权。
- **OIDC Discovery**：解析 `issuer`、授权 / token / JWKS / userinfo 端点与能力列表；
  可由发现文档直接生成 `OAuth2Config`。
- **JWKS 与 ID Token**：只接受 RSA 签名键，按 `kid` 选键（无 `kid` 时要求键唯一），
  过滤 `use=enc` 与 `alg≠RS256` 的键；校验 `iss`、`aud`、多 audience 的 `azp`、
  `exp`、`iat`、可选 `nbf`、`nonce`、`sub`，支持时钟偏移。
- **明确的拒绝路径**：非三段式 token、非法 Base64URL、非 JSON 段、
  不支持的算法、签名不符、弱 RSA 参数、缺字段的发现文档、
  算法不匹配的 JWK，一律抛出具名错误而不是返回半成品。

**明确不做的事**：本库不发起 HTTP 请求、不生成随机数、不做 RSA 密钥生成、
不提供用户信息端点调用与令牌自省，也不实现 ES256 / PS256。这些边界让实现保持
可审计，并把网络、时钟与随机源交给调用方。

## 五、安装方式与快速开始

### 5.1 前置要求

| 依赖 | 版本要求 | 说明 |
| --- | --- | --- |
| MoonBit 工具链 | `moonc` ≥ 0.10.16 | 项目以 MoonBit 为唯一实现语言；0.10.16 为本地实测版本 |
| 编译器后端 | Wasm / WASI | 纯逻辑实现，无需 gcc、Node.js 或系统加密库 |

安装 MoonBit 工具链（Linux / macOS）：

```bash
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash
export PATH="$HOME/.moon/bin:$PATH"
moon version --all
```

Windows 安装包见 <https://www.moonbitlang.com/download/>。

### 5.2 获取项目

```bash
git clone https://github.com/hc155-89/moonjwt.git
cd moonjwt
```

### 5.3 运行示例

```bash
moon run cmd/main --target wasm
```

输出与第三节一致；示例只读取内嵌字节与演示密钥，可离线重复运行。

### 5.4 构建与验证

```bash
moon check --target wasm --deny-warn   # 零告警
moon test --target wasm                # 83 个用例
moon test --target wasm --enable-coverage
moon coverage report -f summary        # 833 / 1019
```

仓库是**库**，`cmd/main` 只是演示三个入口的主包，不提供通用命令行工具；
验证方式是类型检查、测试套件与示例本身。测试向量包含 RFC 7519 附录 A.1 的
HS256 令牌、RFC 7636 附录 B 的 PKCE 向量，以及 OpenSSL 生成的 RS256 签名。

### 5.5 作为依赖安装

本模块目前**尚未发布到 mooncakes.io**，`moon add` 暂时不可用；发布后的安装命令为：

```bash
moon add hc155-89/moonjwt
```

发布之前，请通过 `git clone` 获取源码，并在仓库内运行示例与测试（见 5.2–5.4）。
发布之后，在 `moon.pkg` 中按如下方式声明依赖：

```moonbit
import {
  "hc155-89/moonjwt/core",
  "hc155-89/moonjwt/oauth2",
  "hc155-89/moonjwt/oidc",
}
```

最小使用示例：

```moonbit
fn issue(secret : String) -> String raise {
  let payload = @core.Payload::new()
  payload.set("sub", Json::string("user-42"))
  @core.encode(payload, secret)
}

fn verify(token : String, secret : String) -> String raise {
  let decoded = @core.decode(token, secret)
  match decoded.payload().get("sub") {
    Some(String(subject)) => subject
    _ => "<missing>"
  }
}
```

## 六、技术亮点与实现说明

### 6.1 包结构与职责

| 包 | 职责 | 源码规模 |
| --- | --- | --- |
| `core` | Base64URL、SHA-256、HMAC-SHA256、RSA / PEM / JWK 公钥、JWT 编解码与错误模型 | 942 行 |
| `oauth2` | 客户端配置、授权 URL、PKCE、表单编码、Token Exchange 请求、Token 与错误响应 | 818 行 |
| `oidc` | Discovery 文档、JWKS、ID Token 校验策略、OIDC 错误 | 648 行 |
| `cmd/main` | 可运行演示（签发 / 授权请求 / ID Token 验证） | 137 行 |
| `tests` | OAuth2 与 OIDC 联合的端到端测试（仅测试代码） | 154 行 |

依赖方向单向：`oidc → oauth2 → core`，`cmd/main → {core, oauth2, oidc}`，
`tests → {core, oauth2, oidc}`，不存在环。上表库源码合计 2545 行，另有 1530 行
测试代码，总计 4075 行，低于 5000 行的项目硬约束。

### 6.2 核心技术实现

1. **Base64URL 与 JSON 层（`core/base64url.mbt`、`core/jwt_types.mbt`）。**
   编码只输出 URL 安全字母表且不带 `=` 填充；解码按 4 字符一组还原，拒绝长度
   非法、字符越界、填充位非零的输入，避免同一字节流存在多种写法。Header 只保留
   `alg` / `typ` / `kid`，解析时 `alg` 缺失、非字符串或不在白名单内一律报错；
   Payload 保留完整 claim 映射，使业务声明可以无损往返。
2. **SHA-256 与 HMAC（`core/sha256.mbt`、`core/hmac.mbt`）。** 按 FIPS 180-4
   实现消息扩展与 64 轮压缩，长度以 64 位大端追加；HMAC 按 RFC 2104 先处理
   块长对齐的密钥，再计算 `H(K⊕opad || H(K⊕ipad || msg))`。实现只使用整数运算，
   不依赖宿主加密库，也不做平台相关优化。
3. **RSA 与密钥格式（`core/rsa.mbt`）。** 自建最小 DER 读取器，只接受定长、
   最短编码的长度字段，拒绝 BER 不定长，防止两段不同字节解析成同一把密钥；
   PKCS#1 / PKCS#8 / SPKI 由结构而非 PEM 标签判定类型。签名侧构造
   `EM = 0x00 || 0x01 || 0xFF… || 0x00 || DigestInfo(SHA-256)` 后做模幂，
   校验侧重新编码并做常量时间比较；模数少于 2048 位、公钥指数为偶数或小于 3
   的密钥在解析阶段即被拒绝。
4. **JWT 安全路径（`core/jwt.mbt`）。** HS256 与 RS256 各有独立入口，
   入口先比对 header 声明的算法，再决定使用哪种密钥材料；RS256 路径不会把
   公钥当 HMAC 密钥使用，HS256 路径也不会接受 RSA 头。三条路径都是
   "解析 header → 验签 → 解析 payload"，因此签名失败时调用方拿不到任何 claim。
5. **OAuth2 请求构造（`oauth2/config.mbt`、`oauth2/token_request.mbt`）。**
   授权 URL 的查询参数按固定顺序输出，已有查询串时以 `&` 追加；保留参数
   （`client_id`、`state`、`code_challenge` 等）禁止通过扩展参数覆盖。
   Token 请求按 grant 类型组装表单：机密客户端用
   `base64(form_encode(id) + ":" + form_encode(secret))` 生成 Basic 头且请求体
   不再携带 `client_id`；公共客户端把 `client_id` 放进表单。刷新令牌请求
   刻意不发送 scope，避免请求超出原授权的范围。
6. **PKCE（`oauth2/pkce.mbt`）。** challenge 为
   `BASE64URL(SHA-256(ASCII(verifier)))`；verifier 长度限定 43–128 且只允许
   unreserved 字符。库不自行生成随机数，而是提供 `from_entropy` 接收 32–96 字节
   调用方熵源，既满足 RFC 7636 的长度要求，也避免在 WASI 中假设随机源可用。
7. **OIDC 校验（`oidc/discovery.mbt`、`oidc/jwks.mbt`、`oidc/id_token.mbt`）。**
   Discovery 文档缺少授权端点、token 端点或 JWKS 地址时直接拒绝；JWKS 只解析
   RSA 键并把 `n` / `e` 从 Base64URL 还原为公钥组件。ID Token 的键选择先看
   header 的 `kid`，没有 `kid` 时仅当可用键唯一才继续；验签通过后依次检查
   `iss`、`aud`（多 audience 必须有匹配的 `azp`）、`exp`、`iat`、可选 `nbf`、
   `nonce` 与非空 `sub`。当前时间由调用方传入，测试与 WASI 环境都不依赖宿主时钟。
8. **错误模型。** 三个包各自导出 suberror：`JwtError`（Base64URL、JSON、
   Header、算法、Token、签名、密钥）、`OAuth2Error`（配置、请求、响应）、
   `OidcError`（配置、响应、ID Token）。错误信息带具体原因，例如
   `"RSA modulus must be at least 2048 bits"`，而不是统一的"解析失败"。

### 6.3 数据流

```
JWT 签发
Payload ─► JSON ─► Base64URL ─┐
Header  ─► JSON ─► Base64URL ─┴─► "h.p" ─► HMAC-SHA256 / RSA 签名 ─► Base64URL ─► JWT
```

```
JWT 校验
JWT ─► 三段切分 ─► Header ─► 算法白名单 ─► 验签（常量时间）─► Payload ─► claims
```

```
OAuth2 授权码 + PKCE
verifier ─► SHA-256 ─► Base64URL ─► challenge ─► 授权 URL ─► code
code + verifier ─► 表单编码 ─► Token 请求 ─► access_token / id_token
```

```
OIDC ID Token
Discovery ─► jwks_uri ─► JWKS ─► 按 kid 选键 ─► 公钥 ─► 验签
         ─► iss / aud / azp / exp / iat / nbf / nonce / sub ─► IdToken
```

### 6.4 验证与质量保障

- **CI 门禁**：GitHub Actions 在每次 push 与 pull request 上安装官方工具链，
  执行 `moon check --target wasm --deny-warn`、`moon test --target wasm`
  与 `moon build cmd/main --target wasm`。
- **测试规模**：83 个用例，覆盖 Base64URL 合法 / 非法输入、SHA-256 与 HMAC
  标准向量、PEM 三种格式解析、RS256 外部签名校验、JWT 算法混淆拒绝、
  PKCE 官方向量、授权 URL 精确断言、三种 grant 的请求体、Token 与错误响应、
  Discovery / JWKS 解析、ID Token 的每条校验分支，以及 OAuth2 + OIDC 联合流程。
- **覆盖率**：`moon test --target wasm --enable-coverage` 后
  `moon coverage report -f summary` 为 833 / 1019；未覆盖部分主要是 CLI 演示
  的输出路径与防御性分支。
- **外部参照**：HS256 用例采用 RFC 7519 附录 A.1 的官方令牌；PKCE 用例采用
  RFC 7636 附录 B 的 verifier / challenge；RS256 用例的公钥、私钥与签名由
  OpenSSL 生成，验证实现与独立工具一致。
- **拒绝路径测试**：错误密钥、被篡改 token、`alg: none`、HS256 冒充 RS256、
  未知 `kid`、过期 token、nonce 不匹配、多 audience 缺 `azp`、非 RSA JWK、
  缺 `jwks_uri` 的发现文档均有对应用例。

### 6.5 移植或参考说明

| 项目 | 内容 |
| --- | --- |
| 原项目名称 | 无，本项目为原创实现，不是移植项目 |
| 原项目链接 | 无 |
| 原项目许可证 | 不适用 |
| 本项目许可证 | Apache License 2.0 |

规范依据为 RFC 7519（JWT）、RFC 7515 / 7518（JWS 与算法）、RFC 4648（Base64URL）、
FIPS 180-4（SHA-256）、RFC 2104（HMAC）、RFC 8017（RSA PKCS#1 v1.5）、
RFC 6749（OAuth2）、RFC 7636（PKCE）、RFC 9700（OAuth2 安全最佳实践）、
RFC 7517（JWK）与 OpenID Connect Core / Discovery 1.0。实现代码与文档均为原创，
仅依赖 Apache-2.0 授权的 MoonBit 官方标准库 `moonbitlang/core`。

与完整的认证 SDK 相比，本项目会做以下简化和重新设计：

- **只做协议核心**：不发起 HTTP 请求、不管理令牌存储、不实现回调路由；
  请求以数据结构返回，由调用方决定传输方式。
- **只实现两种算法**：HS256 与 RS256；`none`、ES256、PS256 等显式拒绝，
  不做"自动降级"。
- **随机源外部注入**：PKCE verifier 由调用方提供熵，库内不假设宿主随机源；
  当前时间同样由调用方传入。
- **JWKS 只支持 RSA 签名键**：不实现 EC / OKP，不做远程 JWKS 缓存与轮换；
  一次调用对应一份快照。
- **ID Token 校验不含用户信息**：不调用 userinfo、不做令牌自省，
  只验证签名与注册声明。

开发过程中使用 AI 编程助手辅助代码生成、测试补全与文档撰写；项目的技术路径、
质量边界、验证方式与开源合规由作者负责，所有代码均经过本地编译与单元测试验证。

## 七、后续计划

- [x] 工程骨架与 `moon.mod` / `moon.pkg` 配置
- [x] Base64URL 编解码与 JWT Header / Payload 结构
- [x] 纯 MoonBit SHA-256 / HMAC-SHA256 与 HS256 签发校验
- [x] RSA PKCS#1 v1.5、PEM 解析与 RS256
- [x] OAuth2 配置、PKCE 与授权 URL
- [x] Token Exchange 请求构造与客户端认证
- [x] OIDC Discovery、JWKS 与 ID Token 校验
- [x] 可运行 CLI 演示与端到端测试
- [x] CI 门禁与 Apache-2.0 许可证
- [ ] 远程 JWKS 缓存与密钥轮换
- [ ] ES256 / PS256 支持
- [ ] 用户信息端点与令牌自省封装

---

## 许可证

Copyright 2026 hc155-89.

本项目采用 [Apache License 2.0](./LICENSE) 分发。
