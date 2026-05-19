import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  randomBytes,
  X509Certificate
} from "crypto";
import { requireSupabaseRuntime, supabaseHeaders, supabaseRestUrl, supabaseRpcUrl } from "./infrastructure/supabase";
import { tokenHash } from "./jwt";
import { storeLogger } from "./logger";
import type {
  AuthorizationCode,
  AuthorizationRequest,
  OAuthClient,
  OAuthJwks,
  OAuthPublicJwk,
  OAuthStore,
  PushedAuthorizationRequest,
  StoredAccessToken,
  StoredRefreshToken
} from "./types";

type GlobalWithStore = typeof globalThis & {
  __coreOauthGatewayStore?: OAuthStore;
  __coreOauthGatewayNextSupabaseCleanupAt?: number;
  __coreOauthGatewayClientsLoadedAt?: number;
};

type SupabaseOAuthTokenRow = {
  token_hash: string;
  token_type: "access" | "refresh";
  encrypted_token: string;
  encryption_iv: string;
  encryption_tag: string;
  jwt: string | null;
  client_id: string;
  subject: string;
  scope: string;
  issued_at: number;
  expires_at: number;
  revoked: boolean;
  claims: TokenRecord | null;
  user_claims: TokenRecord | null;
};

type TokenRecord = Record<string, unknown>;

type SupabaseOAuthClientRow = {
  client_id: string;
  client_name: string;
  application_description: string | null;
  client_type: "public" | "confidential";
  client_secret_hash: string | null;
  jwks: OAuthJwks | null;
  jwks_uri: string | null;
  public_key: string | null;
  redirect_uris: string[] | null;
  scopes: string[] | null;
  grant_types: string[] | null;
  auth_methods: string[] | null;
  require_pkce: boolean;
  require_consent: boolean;
  opaque_token: boolean;
  oauth_authentication_provider: string | null;
  backchannel_logout_uri: string | null;
  contact_email: string | null;
  access_token_ttl_seconds: number | null;
  refresh_token_ttl_seconds: number | null;
  session_ttl_seconds: number | null;
  client_metadata: TokenRecord | null;
};

const OAUTH_TOKEN_ENCRYPTION_SECRET =
  process.env.OAUTH_TOKEN_ENCRYPTION_SECRET ?? process.env.SIGNING_KEY_ENCRYPTION_SECRET;
const OAUTH_CLIENT_CACHE_SECONDS = Number(process.env.OAUTH_CLIENT_CACHE_SECONDS ?? 60);
const SUPABASE_CLEANUP_INTERVAL_SECONDS = Number(process.env.SUPABASE_CLEANUP_INTERVAL_SECONDS ?? 300);
const SUPABASE_EXPIRED_TOKEN_RETENTION_SECONDS = Number(
  process.env.SUPABASE_EXPIRED_TOKEN_RETENTION_SECONDS ?? 604800
);

function createStore(): OAuthStore {
  requireSupabaseRuntime();
  return {
    clients: new Map(),
    authorizationRequests: new Map(),
    pushedRequests: new Map(),
    authorizationCodes: new Map(),
    accessTokens: new Map(),
    refreshTokens: new Map()
  };
}

export function getStore(): OAuthStore {
  const globalStore = globalThis as GlobalWithStore;
  if (!globalStore.__coreOauthGatewayStore) {
    globalStore.__coreOauthGatewayStore = createStore();
  }

  return globalStore.__coreOauthGatewayStore;
}

export async function cleanupExpiredRecords(now = Date.now()): Promise<void> {
  await refreshOAuthClients(now);
  await cleanupExpiredSupabaseRecords(now);
  const store = getStore();

  for (const [key, value] of store.authorizationRequests) {
    if (value.expiresAt <= now) {
      store.authorizationRequests.delete(key);
    }
  }

  for (const [key, value] of store.pushedRequests) {
    if (value.expiresAt <= now) {
      store.pushedRequests.delete(key);
    }
  }

  for (const [key, value] of store.authorizationCodes) {
    if (value.expiresAt <= now || value.consumed) {
      store.authorizationCodes.delete(key);
    }
  }
}

export async function refreshOAuthClients(now = Date.now(), force = false): Promise<void> {
  const globalStore = globalThis as GlobalWithStore;
  if (
    !force &&
    globalStore.__coreOauthGatewayClientsLoadedAt &&
    now - globalStore.__coreOauthGatewayClientsLoadedAt < OAUTH_CLIENT_CACHE_SECONDS * 1000
  ) {
    return;
  }

  const rows = await querySupabaseClients();
  const clients = rows.map(rowToOAuthClient);
  getStore().clients = new Map(clients.map((client) => [client.clientId, client]));
  globalStore.__coreOauthGatewayClientsLoadedAt = now;
  storeLogger.info((event) => {
    event
      .message("OAuth clients loaded")
      .tag("oauth")
      .tag("store")
      .tag("clients")
      .with("clientCount", clients.length);
  });
}

export async function findStoredAccessToken(token: string): Promise<StoredAccessToken | undefined> {
  const row = await findSupabaseToken(token, "access");
  return row ? rowToAccessToken(row) : undefined;
}

export async function findStoredRefreshToken(token: string): Promise<StoredRefreshToken | undefined> {
  const row = await findSupabaseToken(token, "refresh");
  return row ? rowToRefreshToken(row) : undefined;
}

export async function listStoredTokens(): Promise<{
  accessTokens: StoredAccessToken[];
  refreshTokens: StoredRefreshToken[];
}> {
  const rows = await querySupabaseTokens({
    activeOnly: true
  });
  return {
    accessTokens: rows.filter((row) => row.token_type === "access").map(rowToAccessToken),
    refreshTokens: rows.filter((row) => row.token_type === "refresh").map(rowToRefreshToken)
  };
}

export async function revokeStoredToken(token: string): Promise<boolean> {
  const updated = await updateSupabaseTokens(
    {
      token_hash: tokenHash(token)
    },
    {
      revoked: true
    },
    true
  );
  return updated > 0;
}

export async function revokeStoredTokenById(tokenId: string): Promise<boolean> {
  const updated = await updateSupabaseTokens(
    {
      token_hash: tokenId
    },
    {
      revoked: true
    },
    true
  );
  return updated > 0;
}

export async function revokeStoredTokensBySubject(
  subject: string | undefined,
  clientIds: string[] | undefined
): Promise<number> {
  return updateSupabaseTokens(
    {
      subject,
      clientIds,
      revoked: false
    },
    {
      revoked: true
    },
    true
  );
}

export async function persistStore(): Promise<void> {
  const store = getStore();
  await persistTokensToSupabase(store);
  store.accessTokens.clear();
  store.refreshTokens.clear();
}

async function findSupabaseToken(
  token: string,
  tokenType: "access" | "refresh"
): Promise<SupabaseOAuthTokenRow | undefined> {
  const rows = await querySupabaseTokens({
    tokenHash: tokenHash(token),
    tokenType
  });
  return rows[0];
}

async function querySupabaseClients(): Promise<SupabaseOAuthClientRow[]> {
  const url = supabaseRestUrl("oauth_clients");
  url.searchParams.set("select", [
    "client_id",
    "client_name",
    "application_description",
    "client_type",
    "client_secret_hash",
    "jwks",
    "jwks_uri",
    "public_key",
    "redirect_uris",
    "scopes",
    "grant_types",
    "auth_methods",
    "require_pkce",
    "require_consent",
    "opaque_token",
    "oauth_authentication_provider",
    "backchannel_logout_uri",
    "contact_email",
    "access_token_ttl_seconds",
    "refresh_token_ttl_seconds",
    "session_ttl_seconds",
    "client_metadata"
  ].join(","));
  url.searchParams.set("active", "eq.true");
  url.searchParams.set("order", "client_id.asc");

  const response = await fetch(url, {
    headers: supabaseHeaders()
  });

  if (!response.ok) {
    throw new Error(`Supabase OAuth client query failed: ${response.status} ${await response.text()}`);
  }

  return (await response.json()) as SupabaseOAuthClientRow[];
}

async function querySupabaseTokens(options: {
  tokenHash?: string;
  tokenType?: "access" | "refresh";
  activeOnly?: boolean;
  subject?: string;
  clientIds?: string[];
}): Promise<SupabaseOAuthTokenRow[]> {
  const url = supabaseRestUrl("oauth_tokens");
  url.searchParams.set("select", [
    "token_hash",
    "token_type",
    "encrypted_token",
    "encryption_iv",
    "encryption_tag",
    "jwt",
    "client_id",
    "subject",
    "scope",
    "issued_at",
    "expires_at",
    "revoked",
    "claims",
    "user_claims"
  ].join(","));
  if (options.tokenHash) url.searchParams.set("token_hash", `eq.${options.tokenHash}`);
  if (options.tokenType) url.searchParams.set("token_type", `eq.${options.tokenType}`);
  if (options.activeOnly) {
    url.searchParams.set("expires_at", `gt.${Date.now()}`);
    url.searchParams.set("revoked", "eq.false");
  }
  if (options.subject) url.searchParams.set("subject", `eq.${options.subject}`);
  if (options.clientIds?.length) {
    url.searchParams.set("client_id", `in.(${options.clientIds.join(",")})`);
  }

  const response = await fetch(url, {
    headers: supabaseHeaders()
  });

  if (!response.ok) {
    throw new Error(`Supabase OAuth token query failed: ${response.status} ${await response.text()}`);
  }

  return (await response.json()) as SupabaseOAuthTokenRow[];
}

async function updateSupabaseTokens(
  filters: {
    token_hash?: string;
    subject?: string;
    clientIds?: string[];
    revoked?: boolean;
  },
  patch: Partial<Pick<SupabaseOAuthTokenRow, "revoked">>,
  count = false
): Promise<number> {
  const url = supabaseRestUrl("oauth_tokens");
  url.searchParams.set("select", "token_hash");
  if (filters.token_hash) url.searchParams.set("token_hash", `eq.${filters.token_hash}`);
  if (filters.subject) url.searchParams.set("subject", `eq.${filters.subject}`);
  if (filters.clientIds?.length) url.searchParams.set("client_id", `in.(${filters.clientIds.join(",")})`);
  if (typeof filters.revoked === "boolean") url.searchParams.set("revoked", `eq.${filters.revoked}`);

  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      ...supabaseHeaders(),
      Prefer: count ? "return=representation" : "return=minimal"
    },
    body: JSON.stringify(patch)
  });

  if (!response.ok) {
    throw new Error(`Supabase OAuth token update failed: ${response.status} ${await response.text()}`);
  }

  if (!count) return response.status === 204 ? 1 : 0;
  const rows = (await response.json()) as Array<{ token_hash: string }>;
  return rows.length;
}

async function cleanupExpiredSupabaseRecords(now: number): Promise<void> {
  const globalStore = globalThis as GlobalWithStore;
  if (globalStore.__coreOauthGatewayNextSupabaseCleanupAt && globalStore.__coreOauthGatewayNextSupabaseCleanupAt > now) {
    return;
  }

  globalStore.__coreOauthGatewayNextSupabaseCleanupAt = now + SUPABASE_CLEANUP_INTERVAL_SECONDS * 1000;
  const response = await fetch(supabaseRpcUrl("oauth_cleanup_expired_records"), {
    method: "POST",
    headers: supabaseHeaders(),
    body: JSON.stringify({
      p_now_ms: now,
      p_delete_expired_older_than_ms: SUPABASE_EXPIRED_TOKEN_RETENTION_SECONDS * 1000
    })
  });

  if (!response.ok && response.status !== 404) {
    throw new Error(`Supabase OAuth cleanup failed: ${response.status} ${await response.text()}`);
  }
  if (response.ok) {
    const result = await response.json().catch(() => ({}));
    storeLogger.info((event) => {
      event
        .message("Supabase OAuth cleanup executed")
        .tag("oauth")
        .tag("store")
        .tag("cleanup")
        .with("result", result);
    });
  }
}

async function persistTokensToSupabase(store: OAuthStore): Promise<void> {
  const rows = [
    ...[...store.accessTokens.values()].map(accessTokenToRow),
    ...[...store.refreshTokens.values()].map(refreshTokenToRow)
  ];
  if (!rows.length) return;

  const url = supabaseRestUrl("oauth_tokens");
  url.searchParams.set("on_conflict", "token_hash");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      ...supabaseHeaders(),
      Prefer: "resolution=merge-duplicates,return=minimal"
    },
    body: JSON.stringify(rows)
  });

  if (!response.ok) {
    throw new Error(`Supabase OAuth token upsert failed: ${response.status} ${await response.text()}`);
  }
  storeLogger.info((event) => {
    event
      .message("OAuth tokens persisted")
      .tag("oauth")
      .tag("store")
      .with("tokenCount", rows.length);
  });
}

function rowToAccessToken(row: SupabaseOAuthTokenRow): StoredAccessToken {
  const token = decryptToken(row);
  return {
    token,
    tokenId: row.token_hash,
    jwt: row.jwt ?? "",
    clientId: row.client_id,
    subject: row.subject,
    scope: row.scope,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revoked: row.revoked,
    claims: row.claims ?? {}
  };
}

function rowToRefreshToken(row: SupabaseOAuthTokenRow): StoredRefreshToken {
  const token = decryptToken(row);
  return {
    token,
    tokenId: row.token_hash,
    clientId: row.client_id,
    subject: row.subject,
    scope: row.scope,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revoked: row.revoked,
    userClaims: row.user_claims ?? {}
  };
}

function rowToOAuthClient(row: SupabaseOAuthClientRow): OAuthClient {
  const jwks = row.jwks?.keys?.length ? row.jwks : publicKeyToJwks(row.public_key);
  const metadata = {
    ...(row.client_metadata ?? {}),
    application_description: row.application_description ?? undefined,
    opaque_token: row.opaque_token,
    oauth_authentication_provider: row.oauth_authentication_provider ?? undefined,
    backchannel_logout_uri: row.backchannel_logout_uri ?? undefined,
    contact_email: row.contact_email ?? undefined,
    access_token_ttl_seconds: row.access_token_ttl_seconds ?? undefined,
    refresh_token_ttl_seconds: row.refresh_token_ttl_seconds ?? undefined,
    session_ttl_seconds: row.session_ttl_seconds ?? undefined
  };

  return {
    clientId: row.client_id,
    clientName: row.client_name,
    type: row.client_type,
    clientSecretHash: row.client_secret_hash ?? undefined,
    jwks,
    jwksUri: row.jwks_uri ?? undefined,
    redirectUris: row.redirect_uris ?? [],
    scopes: row.scopes ?? [],
    grantTypes: row.grant_types ?? [],
    authMethods: row.auth_methods ?? [],
    requirePkce: row.require_pkce,
    requireConsent: row.require_consent,
    opaqueToken: row.opaque_token,
    accessTokenTtlSeconds: row.access_token_ttl_seconds ?? undefined,
    refreshTokenTtlSeconds: row.refresh_token_ttl_seconds ?? undefined,
    sessionTtlSeconds: row.session_ttl_seconds ?? undefined,
    applicationDescription: row.application_description ?? undefined,
    oauthAuthenticationProvider: row.oauth_authentication_provider ?? undefined,
    backchannelLogoutUri: row.backchannel_logout_uri ?? undefined,
    contactEmail: row.contact_email ?? undefined,
    clientMetadata: stripUndefined(metadata)
  };
}

function publicKeyToJwks(publicKey: string | null): OAuthJwks | undefined {
  const jwk = publicKeyToJwk(publicKey);
  if (!jwk) return undefined;

  return {
    keys: [
      {
        ...jwk,
        kid: jwk.kid ?? publicJwkKid(jwk),
        alg: jwk.alg ?? "RS256",
        use: jwk.use ?? "sig"
      }
    ]
  };
}

function publicKeyToJwk(publicKey: string | null): OAuthPublicJwk | undefined {
  const key = publicKey?.trim();
  if (!key) return undefined;

  const candidates: Array<() => OAuthPublicJwk> = [
    () => createPublicKey(key).export({ format: "jwk" }) as OAuthPublicJwk,
    () => new X509Certificate(key).publicKey.export({ format: "jwk" }) as OAuthPublicJwk
  ];

  const base64Der = key
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  if (/^[A-Za-z0-9+/=]+$/.test(base64Der)) {
    const der = Buffer.from(base64Der, "base64");
    candidates.push(
      () => createPublicKey({ key: der, format: "der", type: "spki" }).export({ format: "jwk" }) as OAuthPublicJwk,
      () => new X509Certificate(der).publicKey.export({ format: "jwk" }) as OAuthPublicJwk
    );
  }

  for (const candidate of candidates) {
    try {
      const jwk = candidate();
      if (jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string") {
        return jwk;
      }
    } catch {
      // Try the next supported public-key encoding.
    }
  }

  return undefined;
}

function publicJwkKid(jwk: OAuthPublicJwk): string {
  return createHash("sha256")
    .update(JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e }))
    .digest("base64url");
}

function stripUndefined(record: TokenRecord): TokenRecord {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

function accessTokenToRow(token: StoredAccessToken): SupabaseOAuthTokenRow {
  const encrypted = encryptToken(token.token);
  return {
    token_hash: token.tokenId,
    token_type: "access",
    encrypted_token: encrypted.encryptedToken,
    encryption_iv: encrypted.encryptionIv,
    encryption_tag: encrypted.encryptionTag,
    jwt: token.jwt,
    client_id: token.clientId,
    subject: token.subject,
    scope: token.scope,
    issued_at: token.issuedAt,
    expires_at: token.expiresAt,
    revoked: token.revoked,
    claims: token.claims,
    user_claims: null
  };
}

function refreshTokenToRow(token: StoredRefreshToken): SupabaseOAuthTokenRow {
  const encrypted = encryptToken(token.token);
  return {
    token_hash: token.tokenId,
    token_type: "refresh",
    encrypted_token: encrypted.encryptedToken,
    encryption_iv: encrypted.encryptionIv,
    encryption_tag: encrypted.encryptionTag,
    jwt: null,
    client_id: token.clientId,
    subject: token.subject,
    scope: token.scope,
    issued_at: token.issuedAt,
    expires_at: token.expiresAt,
    revoked: token.revoked,
    claims: null,
    user_claims: token.userClaims
  };
}

function encryptToken(token: string): {
  encryptedToken: string;
  encryptionIv: string;
  encryptionTag: string;
} {
  if (!OAUTH_TOKEN_ENCRYPTION_SECRET) {
    throw new Error(
      "OAUTH_TOKEN_ENCRYPTION_SECRET or SIGNING_KEY_ENCRYPTION_SECRET is required when Supabase token persistence is enabled"
    );
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);

  return {
    encryptedToken: encrypted.toString("base64url"),
    encryptionIv: iv.toString("base64url"),
    encryptionTag: cipher.getAuthTag().toString("base64url")
  };
}

function decryptToken(row: SupabaseOAuthTokenRow): string {
  if (!OAUTH_TOKEN_ENCRYPTION_SECRET) {
    throw new Error(
      "OAUTH_TOKEN_ENCRYPTION_SECRET or SIGNING_KEY_ENCRYPTION_SECRET is required to decrypt persisted OAuth tokens"
    );
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(row.encryption_iv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(row.encryption_tag, "base64url"));
  const token = Buffer.concat([
    decipher.update(Buffer.from(row.encrypted_token, "base64url")),
    decipher.final()
  ]).toString("utf8");

  if (tokenHash(token) !== row.token_hash) {
    throw new Error(`Persisted OAuth token hash mismatch for ${row.token_hash}`);
  }

  return token;
}

function encryptionKey(): Buffer {
  return createHash("sha256").update(OAUTH_TOKEN_ENCRYPTION_SECRET ?? "").digest();
}
