import type { TokenClaims } from "../value-objects/token-claims";

export type StoredAccessToken = {
  token: string;
  tokenId: string;
  oauthFlowId: string;
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
  oauthFlowId: string;
  clientId: string;
  subject: string;
  scope: string;
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
  userClaims: TokenClaims;
};
