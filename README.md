# core-oauth-gateway

`core-oauth-gateway` is a Next.js + TypeScript OAuth2/OIDC authorization server. It is designed for production-style deployments where Supabase is the source of truth for OAuth clients, opaque tokens, signing keys, and `client_assertion` replay protection.

The service keeps public HTTP routes versioned under `/oauth2/v1/*`, supports `private_key_jwt`, JKS/PEM-backed client assertions, JWT bearer grants, opaque-token introspection, and signed JWT access tokens for clients configured with `opaque_token=false`.

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
- `GET /.well-known/openid-configuration`

## Requirements

- Node.js 20 or newer
- npm
- Supabase project with a server-side `service_role` key
- `keytool` and `openssl` if you use JKS-backed client keys

## Local Development

```bash
npm install
cp .env.example .env.local
npm run dev
```

Local examples use `http://127.0.0.1:3000`.

The service does not use local file or in-memory fallbacks for production OAuth state. Configure Supabase before running token flows that need clients, tokens, signing keys, or replay protection.

## Configuration

Set runtime secrets through your platform, not in Git:

```bash
SUPABASE_URL=https://PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
SIGNING_KEY_ENCRYPTION_SECRET=<long-random-secret>
OAUTH_TOKEN_ENCRYPTION_SECRET=<long-random-secret>
AUTH_PROVIDER_LOGIN_URL=http://127.0.0.1:8082/login
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
LOG_LEVEL=INFO
```

`SUPABASE_SERVICE_ROLE_KEY` must be the Supabase `service_role` key. Do not use the `anon` public key on the server.

## Supabase

The `supabase/` directory is intentionally ignored by Git in this workspace. Keep project-specific migrations, seeds, real client IDs, public keys, and environment data outside the public repository unless you have reviewed and sanitized them.

The runtime expects these tables and RPCs to exist in Supabase:

- `oauth_clients`
- `oauth_tokens`
- `oauth_signing_keys`
- `oauth_client_assertion_jtis`
- `oauth_rotate_signing_key`
- `oauth_cleanup_expired_records`

Create OAuth clients per environment. Do not commit real client IDs, client secrets, public keys, JWKS values, JKS files, PEM files, tokens, or exported production data.

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

Never commit generated key material. The repo ignores JKS, PEM, P12/PFX, `.env*`, and local secret folders by default.

Generate a local JKS for a client:

```bash
npm run client:jks -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --out "$JKS_FILE" \
  --alias "$JKS_ALIAS" \
  --storepass "$JKS_STOREPASS" \
  --keypass "$JKS_KEYPASS"
```

The command prints a `public_key`. Store that value in Supabase for the same client.

Generate a PEM key pair instead:

```bash
npm run client:keypair -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --out "$OAUTH_CLIENT_PRIVATE_KEY_FILE"
```

The command prints a JWKS. Store that JWKS in `oauth_clients.jwks`.

## Client Assertions

Create a `private_key_jwt` client assertion from JKS:

```bash
CLIENT_ASSERTION="$(npm run -s client:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --jks "$JKS_FILE" \
  --alias "$JKS_ALIAS" \
  --storepass "$JKS_STOREPASS" \
  --keypass "$JKS_KEYPASS" \
  --aud http://127.0.0.1:3000/oauth2/v1/token)"
```

Create one from a PEM private key:

```bash
CLIENT_ASSERTION="$(npm run -s client:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --key "$OAUTH_CLIENT_PRIVATE_KEY_FILE" \
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

## JWT Bearer Grant

Create a JWT bearer assertion with a dynamic user claim:

```bash
JWT_BEARER_ASSERTION="$(npm run -s jwt-bearer:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --user-id "user-dynamic-789" \
  --jks "$JKS_FILE" \
  --alias "$JKS_ALIAS" \
  --storepass "$JKS_STOREPASS" \
  --keypass "$JKS_KEYPASS" \
  --aud http://127.0.0.1:3000/oauth2/v1/token)"
```

Or with a PEM private key:

```bash
JWT_BEARER_ASSERTION="$(npm run -s jwt-bearer:assertion -- \
  --client-id "$OAUTH_CLIENT_ID" \
  --user-id "user-dynamic-789" \
  --key "$OAUTH_CLIENT_PRIVATE_KEY_FILE" \
  --aud http://127.0.0.1:3000/oauth2/v1/token)"
```

Exchange it for an access token:

```bash
curl -s -X POST http://127.0.0.1:3000/oauth2/v1/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
  -d "assertion=$JWT_BEARER_ASSERTION"
```

If the client has `opaque_token=false`, the returned `access_token` is the signed JWT itself. Otherwise, the service returns an opaque access token that can be checked through `tokeninfo` or introspection.

## Token Operations

Exchange an opaque token for token details:

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

## Render Deployment

`render.yaml` defines a Node web service:

- build command: `npm ci && npm run build`
- start command: `npm run start`
- health check path: `/.well-known/openid-configuration`

Configure all secrets in Render as environment variables. Do not commit production values.

## Postman

Import:

- `postman/core-oauth-gateway.postman_collection.json`
- `postman/core-oauth-gateway.render.postman_environment.json`

Generate assertions locally with the scripts above, then paste the generated assertion into the Postman secret variable.

## Security Checklist

Before pushing:

```bash
npm run security:scan
npm run typecheck
```

The security scan checks for common accidental leaks such as private keys, local key files, hardcoded client IDs, inline keystore passwords, Supabase JWT keys, and old generated key material.

Also confirm that your commit does not include:

- `.env` or `.env.local`
- JKS, PEM, P12/PFX, or private key files
- Supabase service-role keys
- real OAuth client IDs or client secrets
- access tokens, refresh tokens, assertions, or exported production data

## License

This project is distributed under the terms in the repository `LICENSE` file.
