import type { OAuthStateRepositoryPort } from "@/oauth/application/ports/oauth-state.repository.port";
import type {
  AuthorizationCode,
  AuthorizationRequest,
  PushedAuthorizationRequest
} from "@/oauth/domain/entities/authorization";
import type { OAuthAuthenticationProvider } from "@/oauth/domain/entities/oauth-authentication-provider";
import type {
  OAuthClient,
  OAuthClientLookupResult
} from "@/oauth/domain/entities/oauth-client";
import {
  rowToOAuthAuthenticationProvider,
  rowToOAuthClient,
  type SupabaseOAuthAuthenticationProviderRow,
  type SupabaseOAuthClientRow
} from "@/oauth/infrastructure/oauth-client-mapper";
import {
  requireSupabaseRuntime,
  supabaseHeaders,
  supabaseRestUrl
} from "@/oauth/infrastructure/supabase";
import { storeLogger } from "@/oauth/logger";

type OAuthState = {
  clients: Map<string, { active: boolean; client: OAuthClient }>;
  authenticationProviders: Map<string, OAuthAuthenticationProvider>;
  authorizationRequests: Map<string, AuthorizationRequest>;
  pushedRequests: Map<string, PushedAuthorizationRequest>;
  authorizationCodes: Map<string, AuthorizationCode>;
};

type GlobalOAuthState = typeof globalThis & {
  __coreOauthGatewayState?: OAuthState;
  __coreOauthGatewayClientsLoadedAt?: number;
};

export class SupabaseOAuthStateRepository implements OAuthStateRepositoryPort {
  private readonly cacheSeconds = Number(process.env.OAUTH_CLIENT_CACHE_SECONDS ?? 60);

  async refresh(now = Date.now(), force = false): Promise<void> {
    const globalState = globalThis as GlobalOAuthState;
    if (
      !force &&
      globalState.__coreOauthGatewayClientsLoadedAt &&
      now - globalState.__coreOauthGatewayClientsLoadedAt < this.cacheSeconds * 1000
    ) {
      return;
    }

    const [clientRows, providerRows] = await Promise.all([
      queryClients(),
      queryAuthenticationProviders()
    ]);
    const state = getState();
    state.clients = new Map(
      clientRows.map((row) => {
        const client = rowToOAuthClient(row);
        return [client.clientId, { active: row.active, client }];
      })
    );
    state.authenticationProviders = new Map(
      providerRows
        .map(rowToOAuthAuthenticationProvider)
        .map((provider) => [provider.providerId, provider])
    );
    globalState.__coreOauthGatewayClientsLoadedAt = now;
    storeLogger.debug("OAuth clients loaded", {
      clientCount: state.clients.size,
      authenticationProviderCount: state.authenticationProviders.size,
      tags: ["oauth", "store", "clients"]
    });
  }

  async cleanupTransient(now = Date.now()): Promise<void> {
    const state = getState();
    for (const [key, value] of state.authorizationRequests) {
      if (value.expiresAt <= now) state.authorizationRequests.delete(key);
    }
    for (const [key, value] of state.pushedRequests) {
      if (value.expiresAt <= now) state.pushedRequests.delete(key);
    }
    for (const [key, value] of state.authorizationCodes) {
      if (value.expiresAt <= now || value.consumed) state.authorizationCodes.delete(key);
    }
  }

  getClient(clientId: string): OAuthClient | undefined {
    const cached = getState().clients.get(clientId);
    return cached?.active ? cached.client : undefined;
  }

  lookupClient(clientId: string): OAuthClientLookupResult {
    const cached = getState().clients.get(clientId);
    if (!cached) return { status: "not_found" };
    return cached.active
      ? { status: "active", client: cached.client }
      : { status: "inactive", client: cached.client };
  }

  getAuthenticationProvider(providerId: string): OAuthAuthenticationProvider | undefined {
    return getState().authenticationProviders.get(providerId);
  }

  getAuthorizationRequest(oauthKey: string): AuthorizationRequest | undefined {
    return getState().authorizationRequests.get(oauthKey);
  }

  async saveAuthorizationRequest(request: AuthorizationRequest): Promise<void> {
    getState().authorizationRequests.set(request.oauthKey, request);
  }

  async deleteAuthorizationRequest(oauthKey: string): Promise<void> {
    getState().authorizationRequests.delete(oauthKey);
  }

  getPushedRequest(requestUri: string): PushedAuthorizationRequest | undefined {
    return getState().pushedRequests.get(requestUri);
  }

  async savePushedRequest(request: PushedAuthorizationRequest): Promise<void> {
    getState().pushedRequests.set(request.requestUri, request);
  }

  getAuthorizationCode(code: string): AuthorizationCode | undefined {
    return getState().authorizationCodes.get(code);
  }

  async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
    getState().authorizationCodes.set(code.code, code);
  }
}

function getState(): OAuthState {
  requireSupabaseRuntime();
  const globalState = globalThis as GlobalOAuthState;
  if (!globalState.__coreOauthGatewayState) {
    globalState.__coreOauthGatewayState = {
      clients: new Map(),
      authenticationProviders: new Map(),
      authorizationRequests: new Map(),
      pushedRequests: new Map(),
      authorizationCodes: new Map()
    };
  }
  return globalState.__coreOauthGatewayState;
}

async function queryClients(): Promise<SupabaseOAuthClientRow[]> {
  const url = supabaseRestUrl("oauth_clients");
  url.searchParams.set(
    "select",
    [
      "client_id",
      "active",
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
    ].join(",")
  );
  url.searchParams.set("order", "client_id.asc");

  const response = await fetch(url, { headers: supabaseHeaders(), cache: "no-store" });
  if (!response.ok) {
    throw new Error(
      `Supabase OAuth client query failed: ${response.status} ${await response.text()}`
    );
  }
  return (await response.json()) as SupabaseOAuthClientRow[];
}

async function queryAuthenticationProviders(): Promise<SupabaseOAuthAuthenticationProviderRow[]> {
  const url = supabaseRestUrl("oauth_authentication_providers");
  url.searchParams.set(
    "select",
    [
      "provider_id",
      "provider_name",
      "issuer",
      "login_url",
      "jwks",
      "jwks_uri",
      "public_key",
      "user_jwt_max_ttl_seconds",
      "clock_skew_seconds",
      "provider_metadata"
    ].join(",")
  );
  url.searchParams.set("active", "eq.true");
  url.searchParams.set("order", "provider_id.asc");

  const response = await fetch(url, { headers: supabaseHeaders(), cache: "no-store" });
  if (!response.ok) {
    throw new Error(
      `Supabase OAuth authentication-provider query failed: ${response.status} ${await response.text()}`
    );
  }
  return (await response.json()) as SupabaseOAuthAuthenticationProviderRow[];
}
