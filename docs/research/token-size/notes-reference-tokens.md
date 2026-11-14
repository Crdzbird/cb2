# Reference tokens, phantom tokens and server-side token state

Scope: whether cb2 can shrink what the client carries by handing out a short random handle and keeping the full cb2.public (about 4.9 KB) or cb2.local (about 470 chars) token server-side. Research date: 2026-11-07. Items older than 2024 are marked with their date.

## 1. Opaque (reference) tokens vs self-contained tokens: standards and how real vendors format and store them

### Takeaway
The IETF already has the plumbing for reference tokens: RFC 7662 introspection (resource server asks the AS "is this handle active and what are its claims"), RFC 9701 (introspection answer as a signed JWT) and RFC 8693 (token exchange). Industry formats converge on "short random secret + identifying prefix + optional checksum" (GitHub, Ory, Stripe, Slack), but the trend is not one-directional: GitHub moved its App installation tokens in 2026 from a 40-char stateful handle to a ~520-char stateless JWT, accepting size growth to drop a database lookup.

### Cited Findings
Standards
- RFC 7662: the introspection response has one REQUIRED member, `active` (boolean); for an inactive token the AS MUST return `active:false` and SHOULD NOT return other claims. [RFC 7662 s2.2](https://www.rfc-editor.org/rfc/rfc7662.html)
- RFC 7662: the AS MUST require authentication of protected resources calling the endpoint, because an unprotected, unthrottled endpoint lets an attacker "poll a series of possible token values, fishing for a valid token"; POST is preferred so tokens do not land in logs. [RFC 7662 s2.1, s4](https://www.rfc-editor.org/rfc/rfc7662.html)
- RFC 7662 caching: responses may be cached, but a cached response "MUST NOT be cached beyond the time indicated" by `exp`; long caches risk relying on a token that was revoked meanwhile; high-security deployments may disable caching. [RFC 7662 s4](https://www.rfc-editor.org/rfc/rfc7662.html)
- RFC 9701 (January 2025, Standards Track): RS sends `Accept: application/token-introspection+jwt`; AS returns a signed (optionally nested-encrypted) JWT with `typ` `token-introspection+jwt`, `iss`, `aud`, `iat`, and the introspection members under a `token_introspection` claim. The spec says this JWT is not an alternative representation of the access token and must not be used as one. [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701.html)
- Curity Identity Server supports a non-standard `Accept: application/jwt` on introspection that returns the JWT access token directly (the basis of the phantom token pattern). [Kong docs, OIDC with Curity](https://developer.konghq.com/plugins/openid-connect/examples/curity/)

Vendor formats
- GitHub (blog dated 2021-04-05, updated 2023-05-10): prefixes `ghp_` (PAT), `gho_` (OAuth), `ghu_` (user-to-server), `ghs_` (server-to-server), `ghr_` (refresh). Last 6 characters are a CRC32 checksum, Base62-encoded with zero padding, so secret scanning can reject fakes offline without a DB query. OAuth token entropy went from 160 bits (40 hex chars) to 178 bits (30 Base62 chars). Underscore chosen because it is not a Base64 character and double-click selects the whole token. Prefix alone expected to cut secret-scanning false positives to 0.5%. Token length kept unchanged (40 chars). [GitHub blog](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
- GitHub storage: the 2021 blog does not say whether tokens are hashed at rest. [GitHub blog](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
- GitHub current docs list `github_pat_` for fine-grained PATs in addition to the above. [GitHub docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github)
- GitHub 2026 reversal for `ghs_`: staged rollout began 2026-04-27 of a stateless `ghs_APPID_JWT` format; on 2026-10-02 GitHub announced rollout complete, tokens "now about 520 characters long instead of 40". Stateless tokens contain two dots, stateful ones none. Temporary opt-out header `X-GitHub-Stateless-S2S-Token` deprecated 2026-11-30. GitHub tells integrators not to hardcode token length. [GitHub changelog 2026-10-02](https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/); [GitHub docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github); [GitHub changelog 2026-05-15 override header](https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header)
- Ory Hydra opaque tokens: prefixes `ory_at_`, `ory_rt_`, `ory_ac_` (only on opaque tokens, not JWTs), for secret scanning. Example `ory_at_<key>.<signature>`. [Ory token formats](https://www.ory.sh/docs/security-compliance/token-formats)
- Ory Hydra: a valid opaque token needs both the key and the signature; the signature is HMAC-SHA256 under a global system secret, so an attacker who compromises the datastore cannot inject new tokens. [Ory security architecture](https://www.ory.com/docs/hydra/security-architecture); [Ory security overview (older)](https://www.ory.sh/docs/1-hydra/4-security/0-readme)
- Ory storage detail is unconfirmed: a non-official fork page says only the signature is stored; the official doc only says opaque tokens are "stored in a database" and validated by lookup. [Ory JWT vs opaque](https://www.ory.com/docs/oauth2-oidc/jwt-access-token); [fork security page](https://github.com/elliots/hydra/security)
- Auth0: format chosen by `audience`; with an API audience the access token is a JWT, without one an opaque token usable only at /userinfo; community reports no public introspection endpoint for Auth0 opaque tokens. Community-sourced. [Auth0 support article](https://support.auth0.com/center/s/article/value-of-the-audience-attribute-in-access-token-requests-and-its-significance); [Auth0 community](https://community.auth0.com/t/opaque-access-token-introspection/8577)
- Okta: docs describe access tokens as opaque string or JWT, opaque ones validated remotely via introspection; developers report JWT by default and no clear switch. [Okta token lifecycles](https://developer.okta.com/docs/concepts/token-lifecycles/); [Okta support thread](https://support.okta.com/help/s/question/0D51Y00007nuEzFSAU/generate-opaque-access-token-instead-of-jwt-token)
- Keycloak (24+): "lightweight access tokens" are signed JWTs stripped of business claims; full claims come from introspection. A size-reduction-by-reference pattern inside a JWT. [Keycloak forum](https://forum.keycloak.org/t/should-lightweight-access-tokens-always-be-introspected/31363); [FOLIO perf spike on lightweight tokens](https://folio-org.atlassian.net/wiki/spaces/FOLIJET/pages/1575649281/KEYCLOAK-74+Spike+-+Performance+tuning+w+lightweight+access+tokens)
- AWS Cognito: ID and access tokens are readable base64url JWTs; refresh tokens are encrypted and opaque, readable only by the user pool; Cognito warns token size can change. [Cognito developer guide](https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html)
- Google: documented maxima (from a mirror of Google Identity docs): auth code 256 bytes, access token 2048 bytes, refresh token 512 bytes; STS token-exchange access tokens up to 12288 bytes. Google reserves the right to change sizes. [Google STS .NET reference](https://googleapis.dev/dotnet/Google.Apis.CloudSecurityToken.v1/latest/api/Google.Apis.CloudSecurityToken.v1.Data.GoogleIdentityStsV1ExchangeOauthTokenResponse.html); [secondary mirror](https://sites.google.com/site/pawneecity/google-development/google-identity)
- Stripe uses `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`; Slack uses `xoxb-`, `xoxp-`, `xapp-` etc. No official length spec found; a GitLab detection rule uses `(sk|rk)_live_[0-9a-z]{10,128}`. [OpenRouter secret formats](https://openrouter.ai/docs/guides/features/guardrails/secret-formats); [GitLab issue](https://gitlab.com/gitlab-org/gitlab/-/issues/458019)

### Inferences
- A cb2 reference format modelled on GitHub would be: `cb2r_` prefix + 32 random bytes Base62 (43 chars) + 6-char CRC32 = about 54 chars. Base64url of 32 bytes is 43 chars.
- GitHub's 2026 move away from stateful `ghs_` tokens shows the operational cost of the lookup (DB dependency, availability) is real enough that a large provider chose a 13x larger token. cb2 should offer reference handles as an option, not a replacement.
- RFC 9701 is a ready-made standard for the gateway leg if cb2 wants the swapped-in artifact to be standards-shaped, but it is explicitly not the access token itself; a cb2 gateway forwarding the full cb2.public token is closer to Curity's non-standard `application/jwt`.

### Gaps
- No official statement found on how GitHub, Stripe or Slack store tokens (hash or plaintext).
- No official Stripe/Slack length specification found.
- Google's own primary page with 2048/512 limits was not fetched directly; figures come via a mirror and a client-library reference.

## 2. Phantom token and split token patterns, gateway plugins, latency and caching

### Takeaway
Phantom token: client holds an opaque token, gateway introspects and forwards a JWT, caching the result until expiry. Split token: client holds only the JWT signature, gateway keys a cache by SHA-256 of the signature and stores header+payload, so no per-request call to the token service. Implementations exist for NGINX and Kong (Curity) and Kong's own OIDC plugin. No vendor publishes latency numbers.

### Cited Findings
- Phantom token flow (Curity, 2020-03-27): client gets a by-reference token, sends it to the API; a reverse proxy calls introspection to get the by-value JWT and swaps it into the upstream request. Benefits: clients cannot build logic on token contents, no PII leaks to clients, microservices get claims without extra lookups, vendor-neutral. By-value token can be cached until it expires; Curity emits HTTP cache headers for this. No product list or numbers in the article other than an NGINX module. [Curity phantom token](https://curity.io/resources/learn/phantom-token-pattern/)
- Curity NGINX module: [curityio/nginx_phantom_token_module](https://github.com/curityio/nginx_phantom_token_module) (cited from the article above).
- Curity Kong plugin: externalizes introspection and caching; example `token_cache_seconds 900`; version 2.0.1. [curityio/kong-phantom-token-plugin](https://github.com/curityio/kong-phantom-token-plugin)
- Kong's own OpenID Connect plugin supports the phantom token pattern with Curity 3.14+; `config.cache_introspection` defaults to true. [Kong OIDC with Curity](https://developer.konghq.com/plugins/openid-connect/examples/curity/); [Curity Kong integration](https://curity.io/resources/learn/integration-kong/)
- Split token (Curity): token service splits each JWT into signature and head+body; client gets the signature as its opaque token; token service sends SHA-256(signature) and head+body to the gateway; gateway cache key = hash of signature, value = head+body, TTL = token expiry. Gateway reassembles the JWT and forwards it. Designed for CDNs as gateways; recommends allow-listing `iss` and `alg` against cache poisoning and encrypting tokens with PII. A cache dump alone is useless without the client-held signature. Revocation needs cache invalidation. Suggests phantom token as fallback if cache-population delay is a concern. No performance figures. [Curity split token](https://curity.io/resources/learn/split-token-pattern/)

### Inferences
- The split-token pattern is inverted for cb2.public: in a JWT with Ed25519 the signature is the small part, but in cb2.public the ML-DSA-65 signature (3309 bytes, per FIPS 204 parameter set) is most of the 4.9 KB. Handing the client the signature would not shrink anything. The adaptation that works: client gets a random 32-byte handle (or a hash of the signature), gateway caches the whole cb2 token keyed by SHA-256(handle).
- Pushing tokens to the gateway ahead of use (split-token style) avoids the synchronous introspection round trip; phantom style (pull on miss) is simpler and tolerates cold caches. Kong's 900 s example TTL is a reasonable starting point for access tokens with 15-minute lifetimes.

### Gaps
- No published latency or cache-hit-rate figures from Curity, Kong, or anyone else for phantom token introspection. Envoy (ext_authz or OAuth2 filter) and Apigee phantom-token implementations were not found in this pass.

## 3. Storage and lookup design: hash-at-rest, constant time, cache TTLs, revocation, availability

### Takeaway
Store only a hash of the handle (SHA-256 is enough for 128+ bit random handles; HMAC with an app-held key adds DB-leak resistance), look it up by a non-secret selector or by the hash itself, compare in constant time, and cap cache TTL at the token `exp`. Reference tokens give instant revocation but add a hard runtime dependency on the store.

### Cited Findings
- Paragon Initiative split tokens (2017-02-28): 32 random bytes split into a 16-byte selector (stored plaintext, used in the SQL WHERE) and a 16-byte verifier (only its hash stored). Verifier at least 16 bytes and no longer than the hash output. Selector at least 8 bytes with a 32-bit PK or 16 bytes with a 64-bit PK. Plain SHA-256 suffices for high-entropy tokens (no bcrypt); stronger option is HMAC keyed with an application secret the DB never sees, covering verifier, user id and expiry. Compare with `hash_equals()` (constant time). DB string comparison timing can leak the selector but never the verifier. [Paragon IE split tokens](https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels)
- Ory Hydra: HMAC-SHA256 under a system secret means datastore compromise does not allow injecting tokens. [Ory security architecture](https://www.ory.com/docs/hydra/security-architecture)
- Curity split token: storing SHA-256(signature) as cache key means a cache breach alone does not yield usable tokens. [Curity split token](https://curity.io/resources/learn/split-token-pattern/)
- RFC 7662: cache trade-off is freshness vs load; cached results may outlive a revocation; never cache beyond `exp`. [RFC 7662 s4](https://www.rfc-editor.org/rfc/rfc7662.html)
- GitHub's 2026 switch of `ghs_` tokens to stateless JWTs is the clearest public signal that per-request token lookup at scale was worth eliminating. [GitHub changelog](https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/)

### Inferences
- For a cb2 handle of 32 random bytes, a single-column design (key = SHA-256(handle), value = full cb2 token + exp) needs no separate selector: lookup by hash is already constant-time with respect to the secret, because the attacker cannot steer the hash prefix. The selector/verifier split matters mainly when the lookup key must be shorter than a hash or when the DB index is on a truncated value.
- Storage per token: about 4.9 KB (cb2.public) or about 0.5 KB (cb2.local) plus a 32-byte key. One million live public tokens is roughly 5 GB, which fits Redis but is not trivial; cb2.local in the store is 10x cheaper.
- Multi-region: a handle minted in region A is unresolvable in region B until replication lands; mitigations are region-tagged handles (route to home region) or a fallback to introspection at the issuer. No source quantified replication lag for this pattern.

### Gaps
- No sourced Redis TTL guidance or sharding case study specific to reference tokens was found; replication lag figures are not sourced.

## 4. Hybrid designs: handle + MAC, selector/validator, session-ticket style

### Takeaway
Three hybrids reduce lookup cost or eliminate state: (a) handle + checksum or MAC so edges reject garbage offline (GitHub CRC32 for scanners; Ory HMAC for forgery resistance), (b) selector/validator split (Paragon), (c) TLS session-ticket style: encrypt state under a server key so the server keeps no per-client state (RFC 5077), which is what cb2.local already is.

### Cited Findings
- GitHub CRC32 (6 Base62 chars) is for offline validity checks by secret scanners, not a security MAC. [GitHub blog](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
- Ory: `key.signature`, signature = HMAC-SHA256(system secret), both parts required. [Ory security overview](https://www.ory.sh/docs/1-hydra/4-security/0-readme); [Ory token formats](https://www.ory.sh/docs/security-compliance/token-formats)
- RFC 5077 (2008) recommended ticket: `key_name[16]`, `iv[16]`, `encrypted_state<0..2^16-1>` (AES-128-CBC), `mac[32]` (HMAC-SHA-256 over key_name, iv, length and encrypted_state). Overhead 66 bytes plus state. Purpose: resume "without requiring session-specific state at the TLS server". Keys "should be changed regularly"; one option is new keys per server start. [RFC 5077](https://www.rfc-editor.org/rfc/rfc5077.html)

### Inferences
- A "handle + truncated MAC" cb2 reference such as 16-byte random id + 16-byte HMAC-SHA256 tag (keyed with a gateway key) is 32 bytes, 43 Base64url chars, and lets any gateway holding the key reject forged handles with no store hit, closing the RFC 7662 token-scanning concern at the edge.
- The session-ticket model is the stateless middle ground: cb2.local (about 470 chars) already plays this role. The remaining size there is the claim payload plus AEAD overhead, so shrinking it is a payload-encoding problem, not a state problem.
- A key_name field like RFC 5077's maps onto cb2's need for key rotation on any MAC'd handle.

### Gaps
- No published production example of "handle + truncated MAC" specifically for gateway pre-filtering was found beyond Ory's HMAC design.

## 5. Interaction with sender-constrained tokens (DPoP, mTLS) and holder proofs

### Takeaway
Reference tokens compose cleanly with DPoP: the introspection response carries `cnf.jkt` and the resource server checks the binding itself; the DPoP `ath` claim is SHA-256 of the token string actually sent, so a short handle also makes `ath` hashing cheaper.

### Cited Findings
- RFC 9449 s6.2: for introspected tokens the AS conveys the bound key hash as top-level `cnf`/`jkt`; the AS "does not validate an access token's DPoP binding at the introspection endpoint"; the RS validates it locally. If `token_type` is returned it MUST be `DPoP`. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
- RFC 9449 s4.2: `ath` = SHA-256 of the ASCII access token value; binds the proof to that token. `jti` needs at least 96 bits of randomness; servers should reject oversize `jti` or store only a hash. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
- RFC 9449 s8-9: server nonces via `DPoP-Nonce`, must be unpredictable, AS and RS nonces kept separate. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)

### Inferences
- If a gateway swaps a cb2 handle for the full token, the DPoP proof's `ath` covers the handle (what the client sent), so the gateway, not the downstream service, must verify the DPoP proof, or forward the handle so the service can recompute `ath`.
- The client's own DPoP proof (a JWS per request) adds its own header weight; with a PQ signature in the proof the header would again exceed 4 KB, so holder-proof size is a separate problem that reference tokens do not solve.
- mTLS binding (RFC 8705, `cnf.x5t#S256`) behaves the same way through introspection; not fetched in this pass.

### Gaps
- RFC 8705 introspection text not fetched; claim above is by analogy with RFC 9449.

## 6. Size limits that motivate reference tokens (exact current numbers)

### Takeaway
A 4.9 KB cb2.public token fails as a cookie everywhere (4096-octet name+value cap, cookie silently dropped) and sits close to the smallest common per-field header limits (8 KiB nginx/Apache/gRPC metadata) once anything else is added. A 50-char handle fits every limit by two orders of magnitude.

### Cited Findings
- RFC 6265 (2011) s6.1: user agents should support at least 4096 bytes per cookie (name + value + attributes), 50 cookies per domain, 3000 total. [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265#section-6.1)
- RFC 6265bis (draft-ietf-httpbis-rfc6265bis-22, 2025-12-01): if name + value exceeds 4096 octets the UA must "ignore the cookie entirely"; any attribute value over 1024 octets is ignored. [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- nginx: `client_header_buffer_size 1k`; `large_client_header_buffers 4 8k` (request line over one buffer gives 414, a header field over one buffer gives 400); same limits apply to HPACK/QPACK-compressed fields in HTTP/2 and HTTP/3; `max_headers 1000`. [nginx core module](https://nginx.org/en/docs/http/ngx_http_core_module.html)
- Apache httpd 2.4: `LimitRequestFieldSize 8190`, `LimitRequestLine 8190`, `LimitRequestFields 100`. [Apache core](https://httpd.apache.org/docs/2.4/mod/core.html)
- Node.js: `--max-http-header-size` defaults to 16 KiB, raised from 8 KiB in v13.13.0. [Node.js CLI docs](https://nodejs.org/api/cli.html)
- AWS ALB: request line 16 K, single header 16 K, entire request header 64 K, entire response header 32 K, none adjustable. [AWS ALB quotas](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
- Cloudflare: URLs 16 KB; request headers total 128 KB; no per-header limit stated on the page. [Cloudflare connection limits](https://developers.cloudflare.com/fundamentals/reference/connection-limits/) (The brief's "32 KB total / 16 KB per header" figures are superseded by this page.)
- Envoy: `max_request_headers_kb` default 60 KiB, exceeding gives 431; HTTP/2 (nghttp2) single header limit around 100 KB by default (`max_header_field_size_kb`), HTTP/3 around 1024 KB. [Envoy HCM proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto)
- IIS / HTTP.sys: `MaxFieldLength` default 16384 bytes (range 64 to 65534) per header; `MaxRequestBytes` default 16384 (request line + headers, up to 16 MB). [Microsoft Learn HTTP.sys registry](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/iisadmin-service-inetinfo/httpsys-registry-windows)
- Go net/http: `DefaultMaxHeaderBytes = 1 << 20` (1 MB), overridable via `Server.MaxHeaderBytes`. [pkg.go.dev net/http](https://pkg.go.dev/net/http)
- gRPC: metadata guide says servers may limit Request-Headers, suggested default 8 KiB. [gRPC metadata guide](https://grpc.io/docs/guides/metadata/)
- grpc-go: default header list size is still 16 MB in v1.82.0; an env var opts into 8 KB, to become default in a later release. [grpc-go commit #9019](https://chromium.googlesource.com/external/github.com/grpc/grpc-go/+/e80524df97599752f770e6e1bce3b9cc0240d2c1); [release notes via dependency PR](https://github.com/cloudquery/plugin-sdk/pull/2538)
- gRPC core: `grpc.max_metadata_size` soft limit 8 KB; a reported failure at 8689 bytes vs 8192 soft limit. [GitLab issue 577678](https://gitlab.com/gitlab-org/gitlab/-/issues/577678)
- grpc-java (2018 issue): Netty enforced an 8192-byte send-side header limit even without a peer SETTINGS_MAX_HEADER_LIST_SIZE; RFC 7540 default for that setting is unlimited. Current behavior not confirmed. [grpc-java #4284](https://github.com/grpc/grpc-java/issues/4284); [netty #7825](https://github.com/netty/netty/issues/7825)

### Inferences
- cb2.public at about 4.9 KB as a single `Authorization` header passes nginx and Apache defaults (8 KiB) with about 3 KB to spare, but adding a PQ-signed DPoP proof (another few KB) in a second header is fine per-field yet pushes gRPC metadata past its 8 KiB soft limit.
- As a cookie it simply does not work: 6265bis tells browsers to drop it silently.
- A reference handle of 43 to 64 chars removes every one of these constraints; cb2.local (about 470 chars) already fits all of them, so reference handles mainly matter for cb2.public in browsers and gRPC.

### Gaps
- HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE initial value (RFC 9113) not fetched directly; only cited via the netty issue for RFC 7540 ("unlimited").
- Browser-specific enforcement (Chrome, Firefox, Safari) of the 4096 cap and per-domain cookie header totals not checked individually.
- Apache mod_http2 `H2MaxHeaderListSize` default (65536 per unverified model recall) not confirmed from docs.
- Cloudflare per-header limit not stated on its current page.
