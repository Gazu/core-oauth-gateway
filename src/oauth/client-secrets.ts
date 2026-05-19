import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

const DEFAULT_SCRYPT_N = 16384;
const DEFAULT_SCRYPT_R = 8;
const DEFAULT_SCRYPT_P = 1;
const KEY_LENGTH = 64;

type SecretHashParts = {
  n: number;
  r: number;
  p: number;
  salt: Buffer;
  key: Buffer;
};

export function hashClientSecret(secret: string): string {
  const salt = randomBytes(16);
  const key = scryptSync(secret, salt, KEY_LENGTH, {
    N: DEFAULT_SCRYPT_N,
    r: DEFAULT_SCRYPT_R,
    p: DEFAULT_SCRYPT_P
  });

  return [
    "scrypt",
    String(DEFAULT_SCRYPT_N),
    String(DEFAULT_SCRYPT_R),
    String(DEFAULT_SCRYPT_P),
    salt.toString("base64url"),
    key.toString("base64url")
  ].join("$");
}

export function verifyClientSecret(secret: string, expectedHash: string): boolean {
  const parsed = parseClientSecretHash(expectedHash);
  if (!parsed) return false;

  const actual = scryptSync(secret, parsed.salt, parsed.key.length, {
    N: parsed.n,
    r: parsed.r,
    p: parsed.p
  });

  if (actual.length !== parsed.key.length) return false;
  return timingSafeEqual(actual, parsed.key);
}

function parseClientSecretHash(hash: string): SecretHashParts | null {
  const [algorithm, n, r, p, salt, key] = hash.split("$");
  if (algorithm !== "scrypt" || !n || !r || !p || !salt || !key) return null;

  const parsed = {
    n: Number(n),
    r: Number(r),
    p: Number(p),
    salt: Buffer.from(salt, "base64url"),
    key: Buffer.from(key, "base64url")
  };

  if (!Number.isFinite(parsed.n) || !Number.isFinite(parsed.r) || !Number.isFinite(parsed.p)) return null;
  if (!parsed.salt.length || !parsed.key.length) return null;
  return parsed;
}
