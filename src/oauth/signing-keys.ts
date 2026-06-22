import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject
} from "crypto";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  SIGNING_KEY_CACHE_SECONDS,
  SIGNING_KEY_RETENTION_DAYS,
  SIGNING_KEY_ROTATION_DAYS
} from "./config";
import { requireSupabaseRuntime, supabaseHeaders, supabaseRestUrl, supabaseRpcUrl } from "./infrastructure/supabase";
import { signingKeyLogger } from "./logger";

type SigningKeyStatus = "active" | "retiring" | "retired";

export type SigningPublicJwk = JsonWebKey & {
  kid: string;
  alg: "RS256";
  use: "sig";
};

type SigningKeyRecord = {
  kid: string;
  status: SigningKeyStatus;
  algorithm: "RS256";
  use: "sig";
  publicJwk: SigningPublicJwk;
  encryptedPrivateKey: string;
  encryptionIv: string;
  encryptionTag: string;
  createdAt: string;
  activatedAt: string;
  retireAfter: string;
  retiredAt?: string | null;
};

type SupabaseSigningKeyRow = {
  kid: string;
  status: SigningKeyStatus;
  algorithm: "RS256";
  use: "sig";
  public_jwk: SigningPublicJwk;
  encrypted_private_key: string;
  encryption_iv: string;
  encryption_tag: string;
  created_at: string;
  activated_at: string;
  retire_after: string;
  retired_at?: string | null;
};

type GlobalWithSigningKeys = typeof globalThis & {
  __coreOauthGatewaySigningKeyCache?: {
    expiresAt: number;
    keys: SigningKeyRecord[];
  };
};

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const ROTATION_MS = SIGNING_KEY_ROTATION_DAYS * MS_PER_DAY;
const RETENTION_MS = Math.max(SIGNING_KEY_RETENTION_DAYS * MS_PER_DAY, ACCESS_TOKEN_TTL_SECONDS * 1000 * 2);
const CACHE_MS = Math.max(0, SIGNING_KEY_CACHE_SECONDS * 1000);

const SIGNING_KEY_ENCRYPTION_SECRET = process.env.SIGNING_KEY_ENCRYPTION_SECRET;

export async function getActiveSigningKey(): Promise<{ kid: string; privateKey: KeyObject }> {
  let keys = await getUsableSigningKeys();
  let active = newestActiveKey(keys);

  if (!active || shouldRotate(active)) {
    await rotateSigningKeys();
    keys = await getUsableSigningKeys(true);
    active = newestActiveKey(keys);
  }

  if (!active) {
    throw new Error("No active OAuth signing key is available");
  }

  return {
    kid: active.kid,
    privateKey: createPrivateKey(privateKeyPem(active))
  };
}

export async function publicJwks(): Promise<SigningPublicJwk[]> {
  const keys = await getUsableSigningKeys();
  return keys
    .filter((key) => key.status === "active" || key.status === "retiring")
    .sort((a, b) => Date.parse(b.activatedAt) - Date.parse(a.activatedAt))
    .map((key) => key.publicJwk);
}

async function getUsableSigningKeys(forceRefresh = false): Promise<SigningKeyRecord[]> {
  const cache = (globalThis as GlobalWithSigningKeys).__coreOauthGatewaySigningKeyCache;
  if (!forceRefresh && cache && cache.expiresAt > Date.now()) return cache.keys;

  await retireExpiredKeys();
  let keys = await listSigningKeys();
  if (!keys.some((key) => key.status === "active")) {
    await rotateSigningKeys();
    keys = await listSigningKeys();
  }

  const usable = keys.filter((key) => {
    return (key.status === "active" || key.status === "retiring") && Date.parse(key.retireAfter) > Date.now();
  });

  (globalThis as GlobalWithSigningKeys).__coreOauthGatewaySigningKeyCache = {
    expiresAt: Date.now() + CACHE_MS,
    keys: usable
  };

  return usable;
}

async function rotateSigningKeys(): Promise<void> {
  requireSupabaseRuntime();
  const nextKey = createSigningKeyRecord();
  await rotateSupabaseSigningKeys(nextKey);
  signingKeyLogger.info("OAuth signing key rotated", {
    kid: nextKey.kid,
    retireAfter: nextKey.retireAfter,
    backend: "supabase",
    tags: ["oauth", "jwks"]
  });
  (globalThis as GlobalWithSigningKeys).__coreOauthGatewaySigningKeyCache = undefined;
}

function newestActiveKey(keys: SigningKeyRecord[]): SigningKeyRecord | undefined {
  return keys
    .filter((key) => key.status === "active")
    .sort((a, b) => Date.parse(b.activatedAt) - Date.parse(a.activatedAt))[0];
}

function shouldRotate(key: SigningKeyRecord): boolean {
  return Date.now() - Date.parse(key.activatedAt) >= ROTATION_MS;
}

function createSigningKeyRecord(): SigningKeyRecord {
  const now = new Date();
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  const kid = createHash("sha256").update(JSON.stringify(publicJwk)).digest("base64url");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const encrypted = encryptPrivateKey(privateKeyPem);

  return {
    kid,
    status: "active",
    algorithm: "RS256",
    use: "sig",
    publicJwk: {
      ...publicJwk,
      kid,
      alg: "RS256",
      use: "sig"
    },
    ...encrypted,
    createdAt: now.toISOString(),
    activatedAt: now.toISOString(),
    retireAfter: new Date(now.getTime() + RETENTION_MS).toISOString(),
    retiredAt: null
  };
}

function encryptPrivateKey(privateKeyPem: string):
  {
      encryptedPrivateKey: string;
      encryptionIv: string;
      encryptionTag: string;
    } {
  if (!SIGNING_KEY_ENCRYPTION_SECRET) {
    throw new Error("SIGNING_KEY_ENCRYPTION_SECRET is required for production signing-key persistence");
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(privateKeyPem, "utf8"), cipher.final()]);

  return {
    encryptedPrivateKey: encrypted.toString("base64url"),
    encryptionIv: iv.toString("base64url"),
    encryptionTag: cipher.getAuthTag().toString("base64url")
  };
}

function privateKeyPem(record: SigningKeyRecord): string {
  if (!SIGNING_KEY_ENCRYPTION_SECRET) {
    throw new Error("SIGNING_KEY_ENCRYPTION_SECRET is required to decrypt persisted signing keys");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(record.encryptionIv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(record.encryptionTag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.encryptedPrivateKey, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function encryptionKey(): Buffer {
  return createHash("sha256").update(SIGNING_KEY_ENCRYPTION_SECRET ?? "").digest();
}

async function listSigningKeys(): Promise<SigningKeyRecord[]> {
  requireSupabaseRuntime();
  return listSupabaseSigningKeys();
}

async function retireExpiredKeys(): Promise<void> {
  requireSupabaseRuntime();
  await retireExpiredSupabaseSigningKeys();
}

async function listSupabaseSigningKeys(): Promise<SigningKeyRecord[]> {
  const url = supabaseRestUrl("oauth_signing_keys");
  url.searchParams.set("select", [
    "kid",
    "status",
    "algorithm",
    "use",
    "public_jwk",
    "encrypted_private_key",
    "encryption_iv",
    "encryption_tag",
    "created_at",
    "activated_at",
    "retire_after",
    "retired_at"
  ].join(","));
  url.searchParams.set("status", "in.(active,retiring)");
  url.searchParams.set("retire_after", `gt.${new Date().toISOString()}`);
  url.searchParams.set("order", "activated_at.desc");

  const response = await fetch(url, {
    headers: supabaseHeaders(),
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`Supabase signing-key query failed: ${response.status} ${await response.text()}`);
  }

  const rows = (await response.json()) as SupabaseSigningKeyRow[];
  signingKeyLogger.info("OAuth signing keys loaded", {
    keyCount: rows.length,
    backend: "supabase",
    tags: ["oauth", "jwks"]
  });
  return rows.map(rowToRecord);
}

async function rotateSupabaseSigningKeys(nextKey: SigningKeyRecord): Promise<void> {
  if (!nextKey.encryptedPrivateKey || !nextKey.encryptionIv || !nextKey.encryptionTag) {
    throw new Error("Supabase signing keys must be encrypted before persistence");
  }

  const url = supabaseRpcUrl("oauth_rotate_signing_key");
  const response = await fetch(url, {
    method: "POST",
    headers: {
      ...supabaseHeaders(),
      Prefer: "return=representation"
    },
    body: JSON.stringify({
      p_kid: nextKey.kid,
      p_public_jwk: nextKey.publicJwk,
      p_encrypted_private_key: nextKey.encryptedPrivateKey,
      p_encryption_iv: nextKey.encryptionIv,
      p_encryption_tag: nextKey.encryptionTag,
      p_retire_after: nextKey.retireAfter
    })
  });

  if (!response.ok) {
    const active = newestActiveKey(await listSupabaseSigningKeys().catch(() => []));
    if (active) return;
    throw new Error(`Supabase signing-key rotation failed: ${response.status} ${await response.text()}`);
  }
}

async function retireExpiredSupabaseSigningKeys(): Promise<void> {
  const now = new Date().toISOString();
  const url = supabaseRestUrl("oauth_signing_keys");
  url.searchParams.set("status", "neq.retired");
  url.searchParams.set("retire_after", `lt.${now}`);

  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      ...supabaseHeaders(),
      Prefer: "return=minimal"
    },
    body: JSON.stringify({
      status: "retired",
      retired_at: now
    })
  });

  if (!response.ok) {
    throw new Error(`Supabase signing-key retirement failed: ${response.status} ${await response.text()}`);
  }
}

function rowToRecord(row: SupabaseSigningKeyRow): SigningKeyRecord {
  return {
    kid: row.kid,
    status: row.status,
    algorithm: row.algorithm,
    use: row.use,
    publicJwk: row.public_jwk,
    encryptedPrivateKey: row.encrypted_private_key,
    encryptionIv: row.encryption_iv,
    encryptionTag: row.encryption_tag,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    retireAfter: row.retire_after,
    retiredAt: row.retired_at
  };
}
