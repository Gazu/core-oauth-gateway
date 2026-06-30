import { createHash, createPublicKey, X509Certificate } from "crypto";
import type {
  OAuthAuthenticationProvider,
  OAuthClient,
  OAuthJwks,
  OAuthPublicJwk
} from "../types";

type RecordValue = Record<string, unknown>;

export type SupabaseOAuthClientRow = {
  client_id: string;
  active: boolean;
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
  client_metadata: RecordValue | null;
};

export type SupabaseOAuthAuthenticationProviderRow = {
  provider_id: string;
  provider_name: string;
  issuer: string;
  login_url: string;
  jwks: OAuthJwks | null;
  jwks_uri: string | null;
  public_key: string | null;
  user_jwt_max_ttl_seconds: number;
  clock_skew_seconds: number;
  provider_metadata: RecordValue | null;
};

export function rowToOAuthClient(row: SupabaseOAuthClientRow): OAuthClient {
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

export function rowToOAuthAuthenticationProvider(
  row: SupabaseOAuthAuthenticationProviderRow
): OAuthAuthenticationProvider {
  const jwks = row.jwks?.keys?.length ? row.jwks : publicKeyToJwks(row.public_key);
  return {
    providerId: row.provider_id,
    providerName: row.provider_name,
    issuer: row.issuer,
    loginUrl: normalizeAuthenticationProviderLoginUrl(row.login_url, row.provider_id),
    jwks,
    jwksUri: row.jwks_uri ?? undefined,
    userJwtMaxTtlSeconds: row.user_jwt_max_ttl_seconds,
    clockSkewSeconds: row.clock_skew_seconds,
    metadata: row.provider_metadata ?? undefined
  };
}

function normalizeAuthenticationProviderLoginUrl(value: string, providerId: string): string {
  try {
    const loginUrl = new URL(value);
    if (
      (loginUrl.protocol !== "https:" && loginUrl.protocol !== "http:") ||
      loginUrl.username ||
      loginUrl.password
    ) {
      throw new Error("Unsupported login URL");
    }
    return loginUrl.toString();
  } catch {
    throw new Error(`OAuth authentication provider "${providerId}" has an invalid login_url`);
  }
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
      () =>
        createPublicKey({ key: der, format: "der", type: "spki" }).export({
          format: "jwk"
        }) as OAuthPublicJwk,
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

function stripUndefined(record: RecordValue): RecordValue {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}
