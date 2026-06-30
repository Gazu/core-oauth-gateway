import type { TokenClaims } from "../value-objects/token-claims";

export type AuthorizationRequest = {
  oauthKey: string;
  oauthFlowId: string;
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
  oauthFlowId: string;
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
