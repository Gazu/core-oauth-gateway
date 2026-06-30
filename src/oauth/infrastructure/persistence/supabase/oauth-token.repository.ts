import type { TokenRepositoryPort } from "@/oauth/application/ports/token.repository.port";
import type {
  StoredAccessToken,
  StoredRefreshToken
} from "@/oauth/domain/entities/oauth-token";
import {
  supabaseHeaders,
  supabaseRestUrl,
  supabaseRpcUrl
} from "@/oauth/infrastructure/supabase";
import { TokenEncryption } from "@/oauth/infrastructure/security/token-encryption";
import { tokenHash } from "@/oauth/jwt";
import { storeLogger } from "@/oauth/logger";

type TokenRecord = Record<string, unknown>;

type SupabaseOAuthTokenRow = {
  token_hash: string;
  token_type: "access" | "refresh";
  oauth_flow_id: string;
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

type GlobalTokenCleanup = typeof globalThis & {
  __coreOauthGatewayNextSupabaseCleanupAt?: number;
};

export class SupabaseOAuthTokenRepository implements TokenRepositoryPort {
  private readonly encryption = new TokenEncryption();
  private readonly cleanupIntervalSeconds = Number(
    process.env.SUPABASE_CLEANUP_INTERVAL_SECONDS ?? 300
  );
  private readonly expiredRetentionSeconds = Number(
    process.env.SUPABASE_EXPIRED_TOKEN_RETENTION_SECONDS ?? 604800
  );

  async cleanup(now = Date.now()): Promise<void> {
    const globalState = globalThis as GlobalTokenCleanup;
    if (
      globalState.__coreOauthGatewayNextSupabaseCleanupAt &&
      globalState.__coreOauthGatewayNextSupabaseCleanupAt > now
    ) {
      return;
    }

    globalState.__coreOauthGatewayNextSupabaseCleanupAt =
      now + this.cleanupIntervalSeconds * 1000;
    const response = await fetch(supabaseRpcUrl("oauth_cleanup_expired_records"), {
      method: "POST",
      headers: supabaseHeaders(),
      body: JSON.stringify({
        p_now_ms: now,
        p_delete_expired_older_than_ms: this.expiredRetentionSeconds * 1000
      })
    });

    if (!response.ok && response.status !== 404) {
      throw new Error(
        `Supabase OAuth cleanup failed: ${response.status} ${await response.text()}`
      );
    }
    if (response.ok) {
      const result = await response.json().catch(() => ({}));
      storeLogger.debug("Supabase OAuth cleanup executed", {
        result,
        tags: ["oauth", "store", "cleanup"]
      });
    }
  }

  async findAccessToken(token: string): Promise<StoredAccessToken | undefined> {
    const rows = await this.query({ tokenHash: tokenHash(token), tokenType: "access" });
    return rows[0] ? this.rowToAccessToken(rows[0]) : undefined;
  }

  async findRefreshToken(token: string): Promise<StoredRefreshToken | undefined> {
    const rows = await this.query({ tokenHash: tokenHash(token), tokenType: "refresh" });
    return rows[0] ? this.rowToRefreshToken(rows[0]) : undefined;
  }

  async listTokens(): Promise<{
    accessTokens: StoredAccessToken[];
    refreshTokens: StoredRefreshToken[];
  }> {
    const rows = await this.query({ activeOnly: true });
    return {
      accessTokens: rows
        .filter((row) => row.token_type === "access")
        .map((row) => this.rowToAccessToken(row)),
      refreshTokens: rows
        .filter((row) => row.token_type === "refresh")
        .map((row) => this.rowToRefreshToken(row))
    };
  }

  async saveTokens(
    accessToken: StoredAccessToken,
    refreshToken?: StoredRefreshToken
  ): Promise<void> {
    const rows = [
      this.accessTokenToRow(accessToken),
      ...(refreshToken ? [this.refreshTokenToRow(refreshToken)] : [])
    ];
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
      throw new Error(
        `Supabase OAuth token upsert failed: ${response.status} ${await response.text()}`
      );
    }
    storeLogger.debug("OAuth tokens persisted", {
      tokenCount: rows.length,
      tags: ["oauth", "store"]
    });
  }

  async revokeToken(token: string): Promise<boolean> {
    return (await this.update({ tokenHash: tokenHash(token) }, true)) > 0;
  }

  async revokeTokenById(tokenId: string): Promise<boolean> {
    return (await this.update({ tokenHash: tokenId }, true)) > 0;
  }

  revokeTokensBySubject(subject?: string, clientIds?: string[]): Promise<number> {
    return this.update({ subject, clientIds, revoked: false }, true);
  }

  private async query(options: {
    tokenHash?: string;
    tokenType?: "access" | "refresh";
    activeOnly?: boolean;
  }): Promise<SupabaseOAuthTokenRow[]> {
    const url = supabaseRestUrl("oauth_tokens");
    url.searchParams.set(
      "select",
      [
        "token_hash",
        "token_type",
        "oauth_flow_id",
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
      ].join(",")
    );
    if (options.tokenHash) url.searchParams.set("token_hash", `eq.${options.tokenHash}`);
    if (options.tokenType) url.searchParams.set("token_type", `eq.${options.tokenType}`);
    if (options.activeOnly) {
      url.searchParams.set("expires_at", `gt.${Date.now()}`);
      url.searchParams.set("revoked", "eq.false");
    }

    const response = await fetch(url, { headers: supabaseHeaders(), cache: "no-store" });
    if (!response.ok) {
      throw new Error(
        `Supabase OAuth token query failed: ${response.status} ${await response.text()}`
      );
    }
    return (await response.json()) as SupabaseOAuthTokenRow[];
  }

  private async update(
    filters: {
      tokenHash?: string;
      subject?: string;
      clientIds?: string[];
      revoked?: boolean;
    },
    count: boolean
  ): Promise<number> {
    const url = supabaseRestUrl("oauth_tokens");
    url.searchParams.set("select", "token_hash");
    if (filters.tokenHash) url.searchParams.set("token_hash", `eq.${filters.tokenHash}`);
    if (filters.subject) url.searchParams.set("subject", `eq.${filters.subject}`);
    if (filters.clientIds?.length) {
      url.searchParams.set("client_id", `in.(${filters.clientIds.join(",")})`);
    }
    if (typeof filters.revoked === "boolean") {
      url.searchParams.set("revoked", `eq.${filters.revoked}`);
    }

    const response = await fetch(url, {
      method: "PATCH",
      headers: {
        ...supabaseHeaders(),
        Prefer: count ? "return=representation" : "return=minimal"
      },
      body: JSON.stringify({ revoked: true })
    });
    if (!response.ok) {
      throw new Error(
        `Supabase OAuth token update failed: ${response.status} ${await response.text()}`
      );
    }
    if (!count) return response.status === 204 ? 1 : 0;
    return ((await response.json()) as Array<{ token_hash: string }>).length;
  }

  private rowToAccessToken(row: SupabaseOAuthTokenRow): StoredAccessToken {
    return {
      token: this.decryptAndVerify(row),
      tokenId: row.token_hash,
      oauthFlowId: row.oauth_flow_id,
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

  private rowToRefreshToken(row: SupabaseOAuthTokenRow): StoredRefreshToken {
    return {
      token: this.decryptAndVerify(row),
      tokenId: row.token_hash,
      oauthFlowId: row.oauth_flow_id,
      clientId: row.client_id,
      subject: row.subject,
      scope: row.scope,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      revoked: row.revoked,
      userClaims: row.user_claims ?? {}
    };
  }

  private accessTokenToRow(token: StoredAccessToken): SupabaseOAuthTokenRow {
    const encrypted = this.encryption.encrypt(token.token);
    return {
      token_hash: token.tokenId,
      token_type: "access",
      oauth_flow_id: token.oauthFlowId,
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

  private refreshTokenToRow(token: StoredRefreshToken): SupabaseOAuthTokenRow {
    const encrypted = this.encryption.encrypt(token.token);
    return {
      token_hash: token.tokenId,
      token_type: "refresh",
      oauth_flow_id: token.oauthFlowId,
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

  private decryptAndVerify(row: SupabaseOAuthTokenRow): string {
    const token = this.encryption.decrypt(
      row.encrypted_token,
      row.encryption_iv,
      row.encryption_tag
    );
    if (tokenHash(token) !== row.token_hash) {
      throw new Error(`Persisted OAuth token hash mismatch for ${row.token_hash}`);
    }
    return token;
  }
}
