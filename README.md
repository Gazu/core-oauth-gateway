# core-oauth-gateway

`core-oauth-gateway` is a Next.js + TypeScript OAuth2/OIDC authorization server. It is designed for production-style deployments where Supabase is the source of truth for OAuth clients, access and refresh tokens, authentication providers, signing keys, functional audit events, and `client_assertion` replay protection.

The service keeps public HTTP routes versioned under `/oauth2/v1/*`, supports `private_key_jwt`, P12-backed client assertions, JWT bearer grants, opaque-token introspection, and signed JWT access tokens for clients configured with `opaque_token=false`.

Cross-cutting Next.js tracing, structured logging, error presentation, JWT primitives and P12 tooling come from `@smb-tech/service-framework-js@0.2.0`. OAuth protocol responses, Supabase persistence, signing-key rotation and grant-specific rules remain owned by this authorization server.

## Endpoints

- `GET /oauth2/v1/authorize`
- `POST /oauth2/v1/authorize/par`
- `GET /oauth2/v1/consent`
- `POST /oauth2/v1/authdetails`
- `POST /oauth2/v1/userauthorize`
- `POST /oauth2/v1/usererror`
- `POST /oauth2/v1/token`
- `POST /oauth2/v1/tokeninfo`
- `GET /oauth2/v1/certs`
- `POST /oauth2/v1/introspect`
- `POST /oauth2/v1/revoke`
- `POST /oauth2/v1/listAccessTokens`
- `POST /oauth2/v1/revokeById`
- `POST /oauth2/v1/revokeBySID`
- `GET|POST /oauth2/v1/userinfo`
- `GET /health`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/oauth-authorization-server`

## Requirements

- Node.js 20 or newer
- npm
- Supabase project with a server-side `service_role` key

## Local Development

```bash
npm install
cp .env.example .env.local
npm run dev
```

Local examples use `http://127.0.0.1:3000`.

Supabase is mandatory for OAuth clients, tokens, signing keys, and replay protection; there are no local-file fallbacks for those records. Authorization requests, PAR records, and authorization codes are still process-local, so keep a single gateway instance until those records are moved to Supabase.

Authentication-provider routing and signature policy are stored in `oauth_authentication_providers`. The provider-specific `login_url` is the authorization redirect destination, while `user_jwt_max_ttl_seconds` is bounded by the global `AUTH_PROVIDER_JWT_MAX_TTL_SECONDS` ceiling.

## Configuration

Set runtime configuration and secrets through your platform, not in Git:

```bash
SERVICE_NAME=core-oauth-gateway
SERVICE_VERSION=0.1.0
SUPABASE_URL=https://PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
SIGNING_KEY_ENCRYPTION_SECRET=<long-random-secret>
OAUTH_TOKEN_ENCRYPTION_SECRET=<long-random-secret>
AUTH_PROVIDER_JWT_MAX_TTL_SECONDS=300
ACCESS_TOKEN_TTL_SECONDS=300
AUTH_CODE_TTL_SECONDS=60
REQUEST_URI_TTL_SECONDS=60
REFRESH_TOKEN_TTL_SECONDS=3600
SIGNING_KEY_ROTATION_DAYS=30
SIGNING_KEY_RETENTION_DAYS=45
SIGNING_KEY_CACHE_SECONDS=60
OAUTH_CLIENT_CACHE_SECONDS=60
SUPABASE_CLEANUP_INTERVAL_SECONDS=300
SUPABASE_EXPIRED_TOKEN_RETENTION_SECONDS=604800
OAUTH_AUDIT_PERSISTENCE_MODE=all
OAUTH_AUDIT_TIMEOUT_MS=2000
LOG_LEVEL=INFO
```

See [`.env.example`](.env.example) for every supported setting, its default, and its purpose.

`SUPABASE_SERVICE_ROLE_KEY` must be the Supabase `service_role` key. Do not use the `anon` public key on the server.

## Supported Grants

- Authorization Code with S256 PKCE
- Client Credentials
- JWT Bearer (`urn:ietf:params:oauth:grant-type:jwt-bearer`)
- Refresh Token
- Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)
- Resource Owner Password only when `OAUTH_PASSWORD_GRANT_ENABLED=true`

## Supabase

The `supabase/` directory is intentionally ignored by Git in this workspace. Keep project-specific migrations, seeds, real client IDs, public keys, and environment data outside the public repository unless you have reviewed and sanitized them.

The runtime expects these tables and RPCs to exist in Supabase:

- `oauth_clients`
- `oauth_authentication_providers`
- `oauth_tokens`
- `oauth_signing_keys`
- `oauth_client_assertion_jtis`
- `oauth_audit_events`
- `oauth_rotate_signing_key`
- `oauth_cleanup_expired_records`

Create OAuth clients per environment. Do not commit real client IDs, client secrets, public keys, JWKS values, P12/PFX files, PEM files, tokens, or exported production data.

For `private_key_jwt`, configure one of these fields in `oauth_clients`:

- `jwks`: full JWKS JSON, for example `{ "keys": [...] }`
- `jwks_uri`: HTTPS URL that serves the client's JWKS
- `public_key`: PEM public key, PEM certificate, or base64 DER public key

For `client_secret_basic`, store only a hash:

```bash
npm run client:hash-secret -- --secret '<client-secret>'
```

Then save the resulting `scrypt$...` value in `oauth_clients.client_secret_hash`.

## Client Key Material

Never commit generated key material. The repo ignores PEM, P12/PFX, `.env*`, and local secret folders by default.

Use a P12/PFX provisioned through your approved key-management process. Encode it and its password without writing extracted private keys:

```bash
CORE_OAUTH_P12_BASE64="$(npm run -s p12:base64 -- --p12 "$P12_FILE")"
CORE_OAUTH_P12_PASSWORD_BASE64="$(npm run -s p12:password-base64 -- --password "$P12_PASSWORD")"
```

Extract only the matching public key and JWKS using the framework's in-memory P12 loader:

```bash
npm run -s p12:public-key -- \
  --p12 "$P12_FILE" \
  --p12-password "$P12_PASSWORD" \
  --p12-alias "$P12_ALIAS"
```

Store the emitted `public_key` or `jwks` in the matching `oauth_clients` row. Private key material remains inside the P12 and is never written to a temporary file.

## Client Assertions

Create a `private_key_jwt` client assertion from P12:

```bash
CLIENT_ASSERTION="$(npm run -s client:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --p12 "$P12_FILE" \
  --p12-password "$P12_PASSWORD" \
  --p12-alias "$P12_ALIAS" \
  --aud http://127.0.0.1:3000/oauth2/v1/token)"
```

Request a `client_credentials` token:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=standard scope1' \
  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  -d "client_assertion=$CLIENT_ASSERTION"
```

Omit `scope` to request all scopes configured for the client. Any explicitly requested scope must be present in `oauth_clients.scopes`.

## JWT Bearer Grant

Create a JWT bearer assertion with a dynamic user claim:

```bash
JWT_BEARER_ASSERTION="$(npm run -s jwt-bearer:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --user-id "user-dynamic-789" \
  --p12 "$P12_FILE" \
  --p12-password "$P12_PASSWORD" \
  --p12-alias "$P12_ALIAS" \
  --aud http://127.0.0.1:3000/oauth2/v1/token)"
```

Exchange it for an access token:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
  -d "assertion=$JWT_BEARER_ASSERTION"
```

If the client has `opaque_token=false`, the returned `access_token` is the signed JWT itself. Otherwise, the service returns an opaque access token that can be validated through introspection. The compatibility `tokeninfo` endpoint returns the signed JWT representation associated with an access token.

## Token Operations

Exchange an opaque access token for its signed JWT representation:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/tokeninfo \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$ACCESS_TOKEN"
```

Introspect an opaque token:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$ACCESS_TOKEN"
```

Refresh a token without a client assertion:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "refresh_token=$REFRESH_TOKEN"
```

If `scope` is omitted, the refreshed token retains the scopes stored with the refresh token. A supplied scope must remain within the client allowlist.

Revoke either an access token or a refresh token:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/revoke \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$TOKEN"
```

Example active introspection response with custom token claims:

```json
{
  "active": true,
  "user_id": "user-dynamic-789",
  "azp": "<client-id>",
  "client_metadata": {
    "client_key": "bff-quickfade-web",
    "login_token": true,
    "token_format": "opaque"
  },
  "sub": "<subject>",
  "client_id": "<client-id>",
  "scope": "cl:bff:web:profile:read cl:bff:mobile:profile:read",
  "token_type": "Bearer",
  "exp": 1779207540,
  "iat": 1779207240,
  "jti": "2a9c8f2d..."
}
```

Call UserInfo:

```bash
curl -s http://127.0.0.1:3000/oauth2/v1/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Verify a signed JWT against this service JWKS:

```bash
npm run verify:jwt -- "$JWT" \
  --issuer http://127.0.0.1:3000 \
  --jwks http://127.0.0.1:3000/oauth2/v1/certs
```

## Password Grant

Password grant is disabled by default.

To enable it temporarily in a controlled environment, set:

```bash
OAUTH_PASSWORD_GRANT_ENABLED=true
OAUTH_PASSWORD_USERS_JSON='{"user":{"password":"<password>","claims":{"sub":"user"}}}'
```

Do not commit real password-grant users or credentials.

## Audit Events

Functional audit events complement OAuth operational logs; they do not replace them. A UUID `oauthFlowId` is created as soon as `/oauth2/v1/authorize` starts, including rejected requests, and follows a valid authorization request, authorization code, access token, and refresh token. Token-only grants create a new flow identifier. Introspection and revocation recover it from the persisted token.

Every event contains `auditId`, `auditType`, `auditStatus`, `requestId`, `traceId`, `spanId`, `oauthFlowId`, and `eventTimestamp`. Event-specific fields are stored in the same JSON payload. Supported audit types are:

- `authorization_requested`
- `authorization_failed`
- `user_authenticated`
- `authentication_failed`
- `authorization_code_issued`
- `tokens_issued`
- `refresh_token_used`
- `token_revoked`
- `client_authenticated`
- `client_authentication_failed`

Each audit attempt logs `Audit event started` followed by `Audit event completed`. Validation, serialization, timeout, or Supabase persistence failures produce `Audit event failed` with a stable failure reason code. Audit is best-effort: an audit failure never changes or rejects the OAuth response.

`OAUTH_AUDIT_PERSISTENCE_MODE` controls only writes to `oauth_audit_events`:

- `all`: persist successful and failed functional audit events.
- `errors_only`: persist only events whose `auditStatus` is `FAILURE`.
- `disabled`: do not write functional audit events to the table.

Audit lifecycle logs remain enabled in every mode. An unsupported value is reported as `audit_validation_failed` and does not interrupt OAuth.

Tokens, authorization codes, and refresh tokens are represented only as `sha256:<base64url>` hashes. Query a complete flow from Supabase with:

```sql
select event_timestamp, audit_type, audit_status, audit_id, request_id,
       trace_id, span_id, event_payload
from public.oauth_audit_events
where oauth_flow_id = '<oauth-flow-id>'::uuid
order by event_timestamp, audit_id;
```

## Health Check

`GET /health` validates that the service can reach Supabase with the configured server-side credentials. It performs lightweight reads against `oauth_clients` and `oauth_authentication_providers`, including the required provider `login_url` column. It returns `200` when both checks succeed, or `503` when either check fails.

Example:

```bash
curl -s https://core-oauth-gateway.onrender.com/health
```

## Render Deployment

`render.yaml` defines a Node web service:

- build command: `npm ci --include=dev && npm run build`
- start command: `npm run start`
- health check path: `/health`

Configure all secrets in Render as environment variables. Do not commit production values.

## Postman

Import:

- `postman/core-oauth-gateway.postman_collection.json`
- `postman/core-oauth-gateway.render.postman_environment.json`

The committed files are sanitized templates. Set your own `client_id`, scopes, and base URL after import. Generate assertions locally with the P12 commands above, then store the generated values in Postman secret variables.

## Security Checklist

Before pushing:

```bash
npm run lint
npm run typecheck
npm run test
npm run security:scan
npm run build
```

The security scan checks for common accidental leaks such as private keys, local key files, hardcoded client IDs, inline key-material passwords, Supabase JWT keys, and old generated key material.

Also confirm that your commit does not include:

- `.env` or `.env.local`
- PEM, P12/PFX, or private key files
- Supabase service-role keys
- real OAuth client IDs or client secrets
- access tokens, refresh tokens, assertions, or exported production data

## License

This project is distributed under the terms in the repository `LICENSE` file.
