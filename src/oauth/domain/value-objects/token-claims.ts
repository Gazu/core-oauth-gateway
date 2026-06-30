export type TokenClaims = Record<string, unknown>;

export type JwtHeader = {
  typ?: string;
  alg?: string;
  kid?: string;
  [key: string]: unknown;
};

export type JwtPayload = TokenClaims & {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  jti?: string;
};
