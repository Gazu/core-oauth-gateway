import type { JsonWebKey as NodeJsonWebKey } from "crypto";

export type OAuthPublicJwk = NodeJsonWebKey & {
  kid?: string;
  alg?: string;
  use?: string;
};

export type OAuthJwks = {
  keys: OAuthPublicJwk[];
};
