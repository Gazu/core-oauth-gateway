import {
  createHash,
  randomBytes,
  randomUUID,
  type KeyObject
} from "crypto";
import {
  normalizeAudience as frameworkNormalizeAudience,
  nowSeconds as frameworkNowSeconds,
  parseJwt,
  publicKeyFromJwk,
  signJwtRs256,
  verifyJwtRs256
} from "@smb-tech/service-framework-js";
import { getActiveSigningKey, publicJwks } from "./signing-keys";
import type { JwtPayload, OAuthJwks } from "./types";
import type { JwtHeader } from "./domain/value-objects/token-claims";

export async function publicJwkSet() {
  return publicJwks();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

export function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function nowSeconds(): number {
  return frameworkNowSeconds();
}

export function jwtId(): string {
  return randomUUID();
}

export async function signJwt(payload: JwtPayload, header?: Record<string, unknown>): Promise<string> {
  const keyMaterial = await getActiveSigningKey();
  return signJwtWithKey(payload, keyMaterial, header);
}

export function signJwtWithKey(
  payload: JwtPayload,
  keyMaterial: { kid: string; privateKey: KeyObject },
  header?: Record<string, unknown>
): string {
  return signJwtRs256(payload, keyMaterial.privateKey, {
    kid: keyMaterial.kid,
    ...header
  });
}

export function decodeJwt<T extends JwtPayload = JwtPayload>(jwt: string): T | null {
  return (parseJwt(jwt)?.payload as T | undefined) ?? null;
}

export function decodeJwtHeader(jwt: string): JwtHeader | null {
  return (parseJwt(jwt)?.header as JwtHeader | undefined) ?? null;
}

export function verifyJwtSignature(jwt: string, jwks: OAuthJwks): boolean {
  const parts = jwt.split(".");
  if (parts.length !== 3) return false;

  const header = decodeJwtHeader(jwt);
  if (!header || header.alg !== "RS256" || !header.kid) return false;

  const jwk = jwks.keys.find((key) => {
    return key.kid === header.kid && (!key.alg || key.alg === "RS256") && (!key.use || key.use === "sig");
  });
  if (!jwk) return false;

  try {
    return verifyJwtRs256(jwt, publicKeyFromJwk(jwk));
  } catch {
    return false;
  }
}

export function isJwtExpired(payload: JwtPayload, skewSeconds = 0): boolean {
  if (typeof payload.exp !== "number") return false;
  return payload.exp + skewSeconds < nowSeconds();
}

export function normalizeAudience(audience: unknown): string[] {
  return frameworkNormalizeAudience(audience);
}
