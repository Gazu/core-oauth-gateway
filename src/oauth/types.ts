import type { JsonWebKey as NodeJsonWebKey } from "crypto";

export type TokenClaims = Record<string, unknown>;

export type OAuthPublicJwk = NodeJsonWebKey & {
  kid?: string;
  alg?: string;
  use?: string;
};

export type OAuthJwks = {
  keys: OAuthPublicJwk[];
};

export type OAuthClient = {
  clientId: string;
  clientName: string;
  type: "public" | "confidential";
  clientSecretHash?: string;
  jwks?: OAuthJwks;
  jwksUri?: string;
  redirectUris: string[];
  scopes: string[];
  grantTypes: string[];
  authMethods: string[];
  requirePkce?: boolean;
  requireConsent?: boolean;
  opaqueToken?: boolean;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  sessionTtlSeconds?: number;
  applicationDescription?: string;
  oauthAuthenticationProvider?: string;
  backchannelLogoutUri?: string;
  contactEmail?: string;
  clientMetadata?: Record<string, unknown>;
};

export type AuthorizationRequest = {
  oauthKey: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  responseMode?: string;
  authorizationDetails?: unknown;
  consentRequired: boolean;
  clientMetadata?: Record<string, unknown>;
  params: Record<string, string>;
  expiresAt: number;
};

export type PushedAuthorizationRequest = {
  requestUri: string;
  params: Record<string, string>;
  expiresAt: number;
};

export type AuthorizationCode = {
  code: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  authorizationDetails?: unknown;
  userClaims: TokenClaims;
  expiresAt: number;
  consumed: boolean;
};

export type StoredAccessToken = {
  token: string;
  tokenId: string;
  jwt: string;
  clientId: string;
  subject: string;
  scope: string;
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
  claims: TokenClaims;
};

export type StoredRefreshToken = {
  token: string;
  tokenId: string;
  clientId: string;
  subject: string;
  scope: string;
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
  userClaims: TokenClaims;
};

export type OAuthStore = {
  clients: Map<string, OAuthClient>;
  authorizationRequests: Map<string, AuthorizationRequest>;
  pushedRequests: Map<string, PushedAuthorizationRequest>;
  authorizationCodes: Map<string, AuthorizationCode>;
  accessTokens: Map<string, StoredAccessToken>;
  refreshTokens: Map<string, StoredRefreshToken>;
};

export type JwtPayload = Record<string, unknown> & {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  jti?: string;
};
