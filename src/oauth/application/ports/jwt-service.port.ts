import type { OAuthJwks, OAuthPublicJwk } from "../../domain/value-objects/jwk";
import type {
  JwtHeader,
  JwtPayload
} from "../../domain/value-objects/token-claims";

export interface JwtServicePort {
  decode<T extends JwtPayload = JwtPayload>(token: string): T | null;
  decodeHeader(token: string): JwtHeader | null;
  isExpired(payload: JwtPayload, toleranceSeconds?: number): boolean;
  normalizeAudience(audience: unknown): string[];
  verifySignature(token: string, jwks: OAuthJwks): boolean;
  sign(payload: JwtPayload): Promise<string>;
  publicJwks(): Promise<OAuthPublicJwk[]>;
  randomToken(bytes?: number): string;
  tokenHash(token: string): string;
  s256(value: string): string;
  jwtId(): string;
  nowSeconds(): number;
}
