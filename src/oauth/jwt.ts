import {
  createPublicKey,
  createHash,
  createSign,
  createVerify,
  randomBytes,
  randomUUID
} from "crypto";
import { getActiveSigningKey, publicJwks } from "./signing-keys";
import type { JwtPayload, OAuthJwks } from "./types";

export type JwtHeader = {
  typ?: string;
  alg?: string;
  kid?: string;
  [key: string]: unknown;
};

function base64Url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

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
  return Math.floor(Date.now() / 1000);
}

export function jwtId(): string {
  return randomUUID();
}

export async function signJwt(payload: JwtPayload, header?: Record<string, unknown>): Promise<string> {
  const keyMaterial = await getActiveSigningKey();
  const jwtHeader = {
    typ: "JWT",
    alg: "RS256",
    kid: keyMaterial.kid,
    ...header
  };
  const encodedHeader = base64Url(JSON.stringify(jwtHeader));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(keyMaterial.privateKey).toString("base64url");

  return `${signingInput}.${signature}`;
}

export function decodeJwt<T extends JwtPayload = JwtPayload>(jwt: string): T | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;

  try {
    const payload = Buffer.from(parts[1], "base64url").toString("utf8");
    return JSON.parse(payload) as T;
  } catch {
    return null;
  }
}

export function decodeJwtHeader(jwt: string): JwtHeader | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;

  try {
    const header = Buffer.from(parts[0], "base64url").toString("utf8");
    return JSON.parse(header) as JwtHeader;
  } catch {
    return null;
  }
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
    const verifier = createVerify("RSA-SHA256");
    verifier.update(`${parts[0]}.${parts[1]}`);
    verifier.end();
    return verifier.verify(createPublicKey({ key: jwk, format: "jwk" }), parts[2], "base64url");
  } catch {
    return false;
  }
}

export function isJwtExpired(payload: JwtPayload, skewSeconds = 0): boolean {
  if (typeof payload.exp !== "number") return false;
  return payload.exp + skewSeconds < nowSeconds();
}

export function normalizeAudience(audience: unknown): string[] {
  if (Array.isArray(audience)) return audience.filter((entry): entry is string => typeof entry === "string");
  if (typeof audience === "string") return [audience];
  return [];
}
