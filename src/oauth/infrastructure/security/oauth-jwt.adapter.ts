import type { JwtServicePort } from "@/oauth/application/ports/jwt-service.port";
import type {
  OAuthJwks,
  OAuthPublicJwk
} from "@/oauth/domain/value-objects/jwk";
import type { JwtPayload } from "@/oauth/domain/value-objects/token-claims";
import {
  decodeJwt,
  decodeJwtHeader,
  isJwtExpired,
  jwtId,
  normalizeAudience,
  nowSeconds,
  publicJwkSet,
  randomToken,
  s256,
  signJwt,
  tokenHash,
  verifyJwtSignature
} from "@/oauth/jwt";

export class OAuthJwtAdapter implements JwtServicePort {
  decode<T extends JwtPayload = JwtPayload>(token: string): T | null {
    return decodeJwt<T>(token);
  }

  decodeHeader(token: string) {
    return decodeJwtHeader(token);
  }

  isExpired(payload: JwtPayload, toleranceSeconds?: number): boolean {
    return isJwtExpired(payload, toleranceSeconds);
  }

  normalizeAudience(audience: unknown): string[] {
    return normalizeAudience(audience);
  }

  verifySignature(token: string, jwks: OAuthJwks): boolean {
    return verifyJwtSignature(token, jwks);
  }

  sign(payload: JwtPayload): Promise<string> {
    return signJwt(payload);
  }

  async publicJwks(): Promise<OAuthPublicJwk[]> {
    return (await publicJwkSet()) as OAuthPublicJwk[];
  }

  randomToken(bytes?: number): string {
    return randomToken(bytes);
  }

  tokenHash(token: string): string {
    return tokenHash(token);
  }

  s256(value: string): string {
    return s256(value);
  }

  jwtId(): string {
    return jwtId();
  }

  nowSeconds(): number {
    return nowSeconds();
  }
}
