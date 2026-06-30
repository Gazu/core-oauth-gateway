import type { OAuthJwks } from "../value-objects/jwk";

export type OAuthAuthenticationProvider = {
  providerId: string;
  providerName: string;
  issuer: string;
  loginUrl: string;
  jwks?: OAuthJwks;
  jwksUri?: string;
  userJwtMaxTtlSeconds: number;
  clockSkewSeconds: number;
  metadata?: Record<string, unknown>;
};
