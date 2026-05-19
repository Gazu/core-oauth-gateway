export const CLIENT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const JWT_BEARER_GRANT_COMPAT = "urn:ietf:params:grant-type:jwt-bearer";
export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

export const RFC6749_TOKEN_ERROR_URI =
  "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
export const RFC6749_AUTH_ERROR_URI =
  "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
export const RFC7636_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.6";

export const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 300);
export const AUTH_CODE_TTL_SECONDS = Number(process.env.AUTH_CODE_TTL_SECONDS ?? 60);
export const REQUEST_URI_TTL_SECONDS = Number(process.env.REQUEST_URI_TTL_SECONDS ?? 60);
export const REFRESH_TOKEN_TTL_SECONDS = Number(
  process.env.REFRESH_TOKEN_TTL_SECONDS ?? 3600
);
export const SIGNING_KEY_ROTATION_DAYS = Number(process.env.SIGNING_KEY_ROTATION_DAYS ?? 30);
export const SIGNING_KEY_RETENTION_DAYS = Number(process.env.SIGNING_KEY_RETENTION_DAYS ?? 45);
export const SIGNING_KEY_CACHE_SECONDS = Number(process.env.SIGNING_KEY_CACHE_SECONDS ?? 60);

export const AUTH_PROVIDER_LOGIN_URL =
  process.env.AUTH_PROVIDER_LOGIN_URL ?? "http://localhost:8082/login";
export const PASSWORD_GRANT_ENABLED = process.env.OAUTH_PASSWORD_GRANT_ENABLED === "true";
export const PASSWORD_GRANT_USERS_JSON = process.env.OAUTH_PASSWORD_USERS_JSON;

export const SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "standard",
  "scope1",
  "scope2",
  "passport:oauth:introspect:post",
  "postingmanager_sg",
  "testing",
  "baas:ca:auth:test"
];
