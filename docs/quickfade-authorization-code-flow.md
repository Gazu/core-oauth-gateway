# QuickFade Authorization Code Flow

This guide configures and exercises the web/mobile OAuth2 flow between:

- QuickFade web or mobile client
- `core-oauth-gateway`
- `core-login-provider`
- `core-auth-service`

## Supabase setup

Run [`docs/sql/quickfade-authorization-code-clients.sql`](sql/quickfade-authorization-code-clients.sql) in the Supabase SQL Editor after replacing:

- `REPLACE_WITH_LOGIN_PROVIDER_PUBLIC_KEY_BASE64_DER`: RSA public key paired with the private P12 key used by `core-login-provider` to sign `user_jwt`.
- `REPLACE_WITH_WEB_CALLBACK_URL`: exact HTTPS callback URL exposed by the web BFF, including path.

Extract a base64 DER public key from the login-provider P12 without exporting the private key:

```bash
npm run -s p12:public-key -- \
  --p12 "$LOGIN_PROVIDER_P12_FILE" \
  --p12-password "$LOGIN_PROVIDER_P12_PASSWORD" \
  --p12-alias "$LOGIN_PROVIDER_P12_ALIAS"
```

Set `v_login_provider_public_key` to the resulting `public_key` value before executing the SQL.

The mobile callback defaults to `quickfade://auth/callback`. Change it if the native application uses another registered URI scheme or universal link.

Only one of `jwks`, `jwks_uri`, or `public_key` is needed in `oauth_authentication_providers`. The supplied SQL uses `public_key`.

## Authentication-provider field reference

| Field | Value for this flow | Purpose |
| --- | --- | --- |
| `provider_id` | `core-login-provider` | Stable key referenced by `oauth_clients.oauth_authentication_provider`. |
| `provider_name` | Human-readable name | Operational display name. |
| `issuer` | `core-login-provider` | Exact value required in the `user_jwt` `iss` claim. |
| `login_url` | `http://localhost:3002/api/v1/login` locally | HTTP(S) endpoint where the gateway redirects the authorization request. Use the deployed login-provider URL in production. |
| `jwks` | Optional | Inline JWKS used to verify `user_jwt`. |
| `jwks_uri` | Optional HTTPS URL | Remote JWKS endpoint; preferred when the provider rotates keys. |
| `public_key` | Optional RSA public key | Base64 DER, PEM public key, or PEM certificate. Never store the private key. |
| `user_jwt_max_ttl_seconds` | `300` or less | Provider-specific maximum for `exp - iat`. |
| `clock_skew_seconds` | `60` | Allowed clock difference when checking `iat` and `exp`. |
| `provider_metadata` | Non-secret JSON | Operational metadata such as signing algorithm. |
| `active` | `true` | Only active providers are loaded by the gateway. |

Exactly one of `jwks`, `jwks_uri`, or `public_key` must be configured.

## OAuth-client field reference

| Field | Value for this flow | Purpose |
| --- | --- | --- |
| `client_id` | Stable unique ID | Identifies the provider or OAuth client. `oauth_authentication_provider` references this value. |
| `client_name` | Human-readable name | Used in consent and operational views. |
| `application_description` | Component purpose | Operational description; it is not a credential. |
| `client_type` | `public` for web/mobile PKCE clients | Public clients do not authenticate with a shared secret during code exchange. |
| `client_secret_hash` | `null` | No shared secret is used for these PKCE clients. |
| `jwks`, `jwks_uri`, `public_key` | `null` for these public clients | Client-authentication keys are unnecessary because code exchange uses PKCE. |
| `redirect_uris` | Exact callback allowlist | The authorization request and token exchange must use one of these exact values. |
| `scopes` | Allowed scope list | Requests containing any scope outside this list are rejected. |
| `grant_types` | `authorization_code`, `refresh_token` | Enables code exchange and refresh. |
| `auth_methods` | `none` for public clients | PKCE authenticates the authorization-code exchange without a client secret. |
| `require_pkce` | `true` | Requires the authorization request to use PKCE and the exchange to present the verifier. |
| `require_consent` | Product decision | `false` skips the gateway consent requirement; use `true` when explicit consent is required. |
| `opaque_token` | `true` | Returns opaque access tokens that resource servers validate through introspection. |
| `oauth_authentication_provider` | `core-login-provider` | Links each OAuth client to the provider allowed to sign its `user_jwt`. |
| `backchannel_logout_uri` | Optional | Callback for future back-channel logout integration. |
| `contact_email` | Optional operational contact | Do not use a personal address in public fixtures. |
| `access_token_ttl_seconds` | `300` | Access-token lifetime in seconds. |
| `refresh_token_ttl_seconds` | `3600` | Refresh-token lifetime in seconds. |
| `session_ttl_seconds` | `43200` | Session policy metadata; the current token issuer does not enforce a server session from this value. |
| `client_metadata` | Non-secret JSON | Carries application type, token format, and other display/operational metadata. |
| `active` | `true` | Only active clients are loaded by the gateway. |

## Gateway runtime configuration

The login redirect destination comes from
`oauth_authentication_providers.login_url`; it is not an environment variable. Apply
[`sql/add-login-url-to-authentication-providers.sql`](sql/add-login-url-to-authentication-providers.sql)
to existing databases and replace its local URL with the deployed login-provider URL
in production.

The gateway uses the client's `oauth_authentication_provider` value as the stable
`aud` of `oauth_key_signature`. For the supplied SQL configuration,
`core-login-provider` must therefore use `CORE_OAUTH_CLIENT_ID=core-login-provider` in
every environment.

The global JWT lifetime ceiling remains runtime configuration:

```text
AUTH_PROVIDER_JWT_MAX_TTL_SECONDS=300
```

For a fully local flow, configure `core-login-provider` with:

```text
CORE_OAUTH_GATEWAY_BASE_URL=http://localhost:3000
CORE_OAUTH_GATEWAY_USER_AUTHORIZE_URL=http://localhost:3000/oauth2/v1/userauthorize
CORE_OAUTH_GATEWAY_ISSUER=http://localhost:3000
CORE_OAUTH_GATEWAY_CERTS_URL=http://localhost:3000/oauth2/v1/certs
CORE_OAUTH_CLIENT_ID=core-login-provider
CORE_OAUTH_JWT_AUDIENCE=http://localhost:3000
```

The environment value is a global security ceiling. Supabase provides the per-provider policy:

```text
effective user_jwt TTL = min(
  AUTH_PROVIDER_JWT_MAX_TTL_SECONDS,
  oauth_authentication_providers.user_jwt_max_ttl_seconds
)
```

For example, a provider value of `120` with a global ceiling of `300` produces an effective maximum of `120` seconds. A provider value of `600` still produces an effective maximum of `300` seconds.

`core-login-provider` must validate the gateway signature using:

```text
https://core-oauth-gateway.onrender.com/oauth2/v1/certs
```

It must sign `user_jwt` with:

- `alg`: `RS256`
- `kid`: key ID present in the JWKS/public key registered for `core-login-provider`
- `iss`: `core-login-provider`
- `aud`: exact gateway origin, for example `https://core-oauth-gateway.onrender.com`
- `sub`: authenticated user ID
- `iat`: current epoch time
- `exp`: epoch time no more than five minutes after `iat`
- `scope`: approved subset of the scopes requested by the OAuth client

The gateway verifies signature, issuer, audience, subject, issued time, expiry, and scope narrowing before issuing the authorization code.

After updating client rows, wait for `OAUTH_CLIENT_CACHE_SECONDS` or restart the gateway so it reloads the Supabase configuration.

## Manual curl flow

Set environment values:

```bash
GATEWAY_URL='https://core-oauth-gateway.onrender.com'
CLIENT_ID='quickfade-bff-web'
REDIRECT_URI='https://quickfade-bff-web.example.com/auth/callback'
STATE="$(node -e 'console.log(require("node:crypto").randomBytes(16).toString("hex"))')"
CODE_VERIFIER="$(node -e 'console.log(require("node:crypto").randomBytes(64).toString("base64url"))')"
CODE_CHALLENGE="$(CODE_VERIFIER="$CODE_VERIFIER" node -e 'console.log(require("node:crypto").createHash("sha256").update(process.env.CODE_VERIFIER).digest("base64url"))')"
```

### 1. Start authorization

```bash
curl -i -G "$GATEWAY_URL/oauth2/v1/authorize" \
  --data-urlencode 'response_type=code' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode 'scope=openid profile cl:core:profile:read' \
  --data-urlencode "state=$STATE" \
  --data-urlencode "code_challenge=$CODE_CHALLENGE" \
  --data-urlencode 'code_challenge_method=S256'
```

Expected result: `302` with a `Location` pointing to the provider `login_url` and containing `oauth_key` plus `oauth_key_signature`.

In the real flow, the browser follows this redirect and `core-login-provider` authenticates the user through `core-auth-service`.

### 2. Complete authentication at the gateway

This call is normally made by `core-login-provider`, not by the browser. Obtain `OAUTH_KEY` from the redirect and generate `USER_JWT` with the provider P12.

```bash
OAUTH_KEY='<oauth-key-from-authorize-redirect>'
USER_JWT='<rs256-user-jwt-signed-by-core-login-provider>'

AUTHORIZATION_RESPONSE="$(curl -sS -X POST "$GATEWAY_URL/oauth2/v1/userauthorize" \
  -H 'Content-Type: application/json' \
  -d "{\"oauth_key\":\"$OAUTH_KEY\",\"user_jwt\":\"$USER_JWT\"}")"

printf '%s\n' "$AUTHORIZATION_RESPONSE"
AUTHORIZATION_CODE="$(printf '%s' "$AUTHORIZATION_RESPONSE" | node -pe "JSON.parse(require('fs').readFileSync(0, 'utf8')).code")"
```

Example decoded `user_jwt` payload:

```json
{
  "sub": "<user-id>",
  "iss": "core-login-provider",
  "aud": "https://core-oauth-gateway.onrender.com",
  "iat": 1780969787,
  "exp": 1780970087,
  "scope": "openid profile cl:core:profile:read",
  "profile": {
    "email": "user@example.com",
    "username": "demo-user",
    "display_name": "Demo User",
    "role": "member"
  },
  "idt": {
    "sub": "<user-id>",
    "email": "user@example.com",
    "name": "Demo User"
  }
}
```

### 3. Exchange the authorization code

```bash
curl -sS -X POST "$GATEWAY_URL/oauth2/v1/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  --data-urlencode "code=$AUTHORIZATION_CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$CODE_VERIFIER"
```

Expected response:

```json
{
  "access_token": "<opaque-access-token>",
  "refresh_token": "<opaque-refresh-token>",
  "id_token": "<signed-id-token>",
  "scope": "openid profile cl:core:profile:read",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### 4. Introspect the access token

```bash
curl -sS -X POST "$GATEWAY_URL/oauth2/v1/introspect" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS_TOKEN"
```

### 5. Refresh without a client assertion

```bash
curl -sS -X POST "$GATEWAY_URL/oauth2/v1/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
```

### 6. Revoke tokens during logout

```bash
curl -i -X POST "$GATEWAY_URL/oauth2/v1/revoke" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS_TOKEN"

curl -i -X POST "$GATEWAY_URL/oauth2/v1/revoke" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$REFRESH_TOKEN"
```

## Current scaling limitation

Authorization requests, PAR records, and authorization codes are currently held in process memory. Keep a single gateway instance and avoid restarts between authorization and token exchange. Move these records to Supabase before enabling multiple instances or zero-downtime deployments for this flow.
