import type { OAuthApplicationConfig } from "@/oauth/application/ports/oauth-config.port";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTH_CODE_TTL_SECONDS,
  AUTH_PROVIDER_JWT_MAX_TTL_SECONDS,
  CLIENT_ASSERTION_TYPE,
  JWT_BEARER_GRANT,
  JWT_BEARER_GRANT_COMPAT,
  PASSWORD_GRANT_ENABLED,
  PASSWORD_GRANT_USERS_JSON,
  REFRESH_TOKEN_TTL_SECONDS,
  REQUEST_URI_TTL_SECONDS,
  RFC6749_AUTH_ERROR_URI,
  RFC6749_TOKEN_ERROR_URI,
  RFC7636_ERROR_URI,
  SUPPORTED_SCOPES,
  TOKEN_EXCHANGE_GRANT
} from "@/oauth/config";

export function loadOAuthApplicationConfig(): OAuthApplicationConfig {
  return {
    clientAssertionType: CLIENT_ASSERTION_TYPE,
    jwtBearerGrant: JWT_BEARER_GRANT,
    jwtBearerGrantCompat: JWT_BEARER_GRANT_COMPAT,
    tokenExchangeGrant: TOKEN_EXCHANGE_GRANT,
    tokenErrorUri: RFC6749_TOKEN_ERROR_URI,
    authorizationErrorUri: RFC6749_AUTH_ERROR_URI,
    pkceErrorUri: RFC7636_ERROR_URI,
    accessTokenTtlSeconds: ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: REFRESH_TOKEN_TTL_SECONDS,
    authorizationCodeTtlSeconds: AUTH_CODE_TTL_SECONDS,
    requestUriTtlSeconds: REQUEST_URI_TTL_SECONDS,
    authenticationProviderJwtMaxTtlSeconds: AUTH_PROVIDER_JWT_MAX_TTL_SECONDS,
    passwordGrantEnabled: PASSWORD_GRANT_ENABLED,
    passwordGrantUsersJson: PASSWORD_GRANT_USERS_JSON,
    supportedScopes: [...SUPPORTED_SCOPES]
  };
}
