export type OAuthApplicationConfig = {
  clientAssertionType: string;
  jwtBearerGrant: string;
  jwtBearerGrantCompat: string;
  tokenExchangeGrant: string;
  tokenErrorUri: string;
  authorizationErrorUri: string;
  pkceErrorUri: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  requestUriTtlSeconds: number;
  authenticationProviderJwtMaxTtlSeconds: number;
  passwordGrantEnabled: boolean;
  passwordGrantUsersJson?: string;
  supportedScopes: string[];
};
