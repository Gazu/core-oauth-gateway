import type { OAuthJwks } from "../value-objects/jwk";

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

export type OAuthClientLookupResult =
  | { status: "active"; client: OAuthClient }
  | { status: "inactive"; client: OAuthClient }
  | { status: "not_found" };
