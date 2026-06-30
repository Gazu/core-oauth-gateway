import { vi } from "vitest";
import type { OAuthApplicationPorts } from "../../../src/oauth/application/ports/oauth-application.ports";

const logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};

export function createTestOAuthPorts(
  overrides: Partial<OAuthApplicationPorts> = {}
): OAuthApplicationPorts {
  return {
    state: {
      refresh: vi.fn(async () => undefined),
      cleanupTransient: vi.fn(async () => undefined),
      getClient: vi.fn(() => undefined),
      lookupClient: vi.fn(() => ({ status: "not_found" as const })),
      getAuthenticationProvider: vi.fn(() => undefined),
      getAuthorizationRequest: vi.fn(() => undefined),
      saveAuthorizationRequest: vi.fn(async () => undefined),
      deleteAuthorizationRequest: vi.fn(async () => undefined),
      getPushedRequest: vi.fn(() => undefined),
      savePushedRequest: vi.fn(async () => undefined),
      getAuthorizationCode: vi.fn(() => undefined),
      saveAuthorizationCode: vi.fn(async () => undefined)
    },
    tokens: {
      cleanup: vi.fn(async () => undefined),
      findAccessToken: vi.fn(async () => undefined),
      findRefreshToken: vi.fn(async () => undefined),
      listTokens: vi.fn(async () => ({ accessTokens: [], refreshTokens: [] })),
      saveTokens: vi.fn(async () => undefined),
      revokeToken: vi.fn(async () => false),
      revokeTokenById: vi.fn(async () => false),
      revokeTokensBySubject: vi.fn(async () => 0)
    },
    jwt: {
      decode: vi.fn(() => null),
      decodeHeader: vi.fn(() => null),
      isExpired: vi.fn(() => false),
      normalizeAudience: vi.fn(() => []),
      verifySignature: vi.fn(() => false),
      sign: vi.fn(async () => "signed.jwt.value"),
      publicJwks: vi.fn(async () => []),
      randomToken: vi.fn(() => "random-token"),
      tokenHash: vi.fn((value: string) => `hash:${value}`),
      s256: vi.fn((value: string) => `s256:${value}`),
      jwtId: vi.fn(() => "jwt-id"),
      nowSeconds: vi.fn(() => 1_700_000_000)
    },
    audit: {
      record: vi.fn(async (input) => ({
        auditId: "audit-id",
        auditType: input.auditType,
        auditStatus: input.auditStatus,
        oauthFlowId: input.oauthFlowId,
        persisted: true
      })),
      newFlowId: vi.fn(() => "oauth-flow-id"),
      hash: vi.fn((value: string) => `sha256:${value}`),
      correlation: vi.fn(() => ({ auditId: "audit-id" }))
    },
    replay: {
      remember: vi.fn(async () => true)
    },
    clientSecrets: {
      verify: vi.fn(() => true)
    },
    remoteJwks: {
      resolve: vi.fn(async () => null)
    },
    health: {
      check: vi.fn(async () => ({ ok: true as const, latencyMs: 1 }))
    },
    loggers: {
      oauth: logger,
      token: logger,
      clientAuth: logger
    },
    config: {
      clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      jwtBearerGrant: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      jwtBearerGrantCompat: "urn:ietf:params:grant-type:jwt-bearer",
      tokenExchangeGrant: "urn:ietf:params:oauth:grant-type:token-exchange",
      tokenErrorUri: "https://www.rfc-editor.org/rfc/rfc6749#section-5.2",
      authorizationErrorUri: "https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1",
      pkceErrorUri: "https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1",
      accessTokenTtlSeconds: 300,
      refreshTokenTtlSeconds: 3600,
      authorizationCodeTtlSeconds: 60,
      requestUriTtlSeconds: 60,
      authenticationProviderJwtMaxTtlSeconds: 300,
      passwordGrantEnabled: false,
      supportedScopes: ["openid", "profile"]
    },
    maintenance: {
      cleanup: vi.fn(async () => undefined)
    },
    ...overrides
  };
}
