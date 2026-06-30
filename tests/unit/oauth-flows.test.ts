import { describe, expect, it, vi } from "vitest";
import { IssueTokenUseCase } from "../../src/oauth/application/use-cases/issue-token-use-case";
import { IntrospectTokenUseCase } from "../../src/oauth/application/use-cases/token-query-use-cases";
import { RevokeTokenUseCase } from "../../src/oauth/application/use-cases/token-revocation-use-cases";
import type { OAuthClient } from "../../src/oauth/domain/entities/oauth-client";
import type {
  StoredAccessToken,
  StoredRefreshToken
} from "../../src/oauth/domain/entities/oauth-token";
import { createTestOAuthPorts } from "./helpers/oauth-ports";

const baseUrl = "https://oauth.example.com";

describe("OAuth application flows", () => {
  it("issues, refreshes, introspects and revokes an opaque JWT bearer token", async () => {
    const ports = createTestOAuthPorts();
    const client = oauthClient({
      grantTypes: [ports.config.jwtBearerGrant, "refresh_token"],
      authMethods: ["private_key_jwt"],
      jwks: { keys: [{ kty: "RSA", kid: "client-key", alg: "RS256", use: "sig" }] }
    });
    const accessTokens = new Map<string, StoredAccessToken>();
    const refreshTokens = new Map<string, StoredRefreshToken>();
    const generatedTokens = ["access-token-1", "refresh-token-1", "access-token-2", "refresh-token-2"];
    const assertionClaims = {
      iss: client.clientId,
      sub: "user-789",
      user_id: "user-789",
      aud: `${baseUrl}/oauth2/v1/token`,
      jti: "assertion-jti",
      exp: 1_800_000_300,
      scope: "openid profile"
    };

    ports.state.getClient = vi.fn(() => client);
    ports.state.lookupClient = vi.fn(() => ({ status: "active" as const, client }));
    vi.mocked(ports.jwt.decode).mockReturnValue(assertionClaims);
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256", kid: "client-key" }));
    ports.jwt.normalizeAudience = vi.fn(() => [`${baseUrl}/oauth2/v1/token`]);
    ports.jwt.verifySignature = vi.fn(() => true);
    ports.jwt.nowSeconds = vi.fn(() => Math.floor(Date.now() / 1000));
    ports.remoteJwks.resolve = vi.fn(async () => client.jwks ?? null);
    ports.jwt.randomToken = vi.fn(() => generatedTokens.shift() ?? "unexpected-token");
    ports.tokens.saveTokens = vi.fn(async (accessToken, refreshToken) => {
      accessTokens.set(accessToken.token, accessToken);
      if (refreshToken) refreshTokens.set(refreshToken.token, refreshToken);
    });
    ports.tokens.findAccessToken = vi.fn(async (token) => accessTokens.get(token));
    ports.tokens.findRefreshToken = vi.fn(async (token) => refreshTokens.get(token));
    ports.tokens.revokeToken = vi.fn(async (token) => {
      const stored = accessTokens.get(token) ?? refreshTokens.get(token);
      if (!stored) return false;
      stored.revoked = true;
      return true;
    });

    const issueToken = new IssueTokenUseCase(ports);
    const issued = await issueToken.execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: ports.config.jwtBearerGrant,
        assertion: "header.payload.signature"
      }
    });

    expect(issued).toMatchObject({
      status: 200,
      body: {
        access_token: "access-token-1",
        refresh_token: "refresh-token-1",
        scope: "openid profile"
      }
    });

    const introspection = new IntrospectTokenUseCase(ports);
    await expect(introspection.execute({ token: "access-token-1" })).resolves.toMatchObject({
      status: 200,
      body: {
        active: true,
        sub: "user-789",
        user_id: "user-789",
        client_id: client.clientId,
        scope: "openid profile"
      }
    });

    const refreshed = await issueToken.execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: "refresh_token",
        refresh_token: "refresh-token-1"
      }
    });
    expect(refreshed).toMatchObject({
      status: 200,
      body: {
        access_token: "access-token-2",
        refresh_token: "refresh-token-2",
        scope: "openid profile"
      }
    });

    const revoked = await new RevokeTokenUseCase(ports).execute({ token: "access-token-1" });
    expect(revoked.status).toBe(200);
    await expect(introspection.execute({ token: "access-token-1" })).resolves.toMatchObject({
      status: 200,
      body: { active: false }
    });
  });

  it("exchanges an authorization code once and validates S256 PKCE", async () => {
    const ports = createTestOAuthPorts();
    const client = oauthClient({
      grantTypes: ["authorization_code", "refresh_token"],
      authMethods: ["none"],
      requirePkce: true
    });
    const authorizationCode = {
      code: "authorization-code",
      oauthFlowId: "authorization-flow",
      clientId: client.clientId,
      redirectUri: "https://app.example.com/callback",
      scope: "openid profile",
      codeChallenge: "pkce-challenge",
      codeChallengeMethod: "S256",
      userClaims: { sub: "user-123", user_id: "user-123" },
      expiresAt: Date.now() + 60_000,
      consumed: false
    };

    ports.state.getClient = vi.fn(() => client);
    ports.state.getAuthorizationCode = vi.fn(() => authorizationCode);
    ports.jwt.s256 = vi.fn(() => "pkce-challenge");
    ports.jwt.randomToken = vi.fn()
      .mockReturnValueOnce("authorization-access-token")
      .mockReturnValueOnce("authorization-refresh-token");

    const response = await new IssueTokenUseCase(ports).execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: "authorization_code",
        client_id: client.clientId,
        code: authorizationCode.code,
        redirect_uri: authorizationCode.redirectUri,
        code_verifier: "pkce-verifier"
      }
    });

    expect(response).toMatchObject({
      status: 200,
      body: {
        access_token: "authorization-access-token",
        refresh_token: "authorization-refresh-token",
        scope: "openid profile",
        id_token: "signed.jwt.value"
      }
    });
    expect(authorizationCode.consumed).toBe(true);
    expect(ports.state.saveAuthorizationCode).toHaveBeenCalledWith(authorizationCode);

    const replay = await new IssueTokenUseCase(ports).execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: "authorization_code",
        client_id: client.clientId,
        code: authorizationCode.code,
        code_verifier: "pkce-verifier"
      }
    });
    expect(replay).toMatchObject({
      status: 400,
      error: { code: "invalid_grant" }
    });
  });

  it("propagates a JWT bearer root cause to the audit event", async () => {
    const ports = createTestOAuthPorts();
    const rawAssertion = "sensitive-header.sensitive-payload.sensitive-signature";
    vi.mocked(ports.jwt.decode).mockReturnValue({
      iss: "expired-client",
      aud: `${baseUrl}/oauth2/v1/token`,
      exp: 1_700_000_000,
      jti: "expired-jti"
    });
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256", kid: "client-key" }));
    ports.jwt.isExpired = vi.fn(() => true);

    const response = await new IssueTokenUseCase(ports).execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: ports.config.jwtBearerGrant,
        assertion: rawAssertion
      }
    });

    expect(response).toMatchObject({
      status: 400,
      error: {
        code: "invalid_grant",
        description: "OAuth 2.0 Parameter: assertion"
      }
    });
    expect(JSON.stringify(response)).not.toContain("assertion_expired");
    expect(JSON.stringify(response)).not.toContain("expired-client");
    expect(ports.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        auditType: "client_authentication_failed",
        auditStatus: "FAILURE",
        reasonCode: "invalid_client_assertion",
        rootCauseCode: "assertion_expired",
        details: expect.objectContaining({ clientId: "expired-client" })
      })
    );
    expect(ports.loggers.clientAuth.error).toHaveBeenCalledWith(
      "Client authentication failed",
      expect.objectContaining({
        reasonCode: "invalid_client_assertion",
        rootCauseCode: "assertion_expired"
      })
    );
    const observabilityPayload = JSON.stringify({
      auditCalls: vi.mocked(ports.audit.record).mock.calls,
      logCalls: vi.mocked(ports.loggers.clientAuth.error).mock.calls
    });
    expect(observabilityPayload).not.toContain(rawAssertion);
    expect(observabilityPayload).not.toContain("sensitive-payload");
  });

  it("keeps private_key_jwt authentication errors generic", async () => {
    const ports = createTestOAuthPorts();
    vi.mocked(ports.jwt.decode).mockReturnValue({
      iss: "expired-client",
      sub: "expired-client",
      aud: `${baseUrl}/oauth2/v1/token`,
      exp: 1_700_000_000,
      jti: "expired-jti"
    });
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256", kid: "client-key" }));
    ports.jwt.isExpired = vi.fn(() => true);

    const response = await new IssueTokenUseCase(ports).execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: {},
      parameters: {
        grant_type: "client_credentials",
        client_assertion_type: ports.config.clientAssertionType,
        client_assertion: "header.payload.signature"
      }
    });

    expect(response).toMatchObject({
      status: 401,
      error: {
        code: "invalid_client",
        description: "Client authentication failed"
      },
      headers: {
        "WWW-Authenticate": expect.stringContaining(
          'error_description="Client authentication failed"'
        )
      }
    });
    const serialized = JSON.stringify(response);
    expect(serialized).not.toContain("assertion_expired");
    expect(serialized).not.toContain("expired-client");
    expect(serialized).not.toContain("signature");
    expect(serialized).not.toContain("jti");
  });

  it("continues issuing tokens when audit persistence reports a failure", async () => {
    const ports = createTestOAuthPorts();
    const client = oauthClient({
      type: "confidential",
      clientSecretHash: "encoded-secret-hash",
      grantTypes: ["client_credentials"],
      authMethods: ["client_secret_basic"]
    });
    ports.state.getClient = vi.fn(() => client);
    ports.audit.record = vi.fn(async (input) => ({
      auditId: "failed-audit-id",
      auditType: input.auditType,
      auditStatus: input.auditStatus,
      oauthFlowId: input.oauthFlowId,
      persisted: false,
      failureReasonCode: "audit_persistence_failed"
    }));
    ports.jwt.randomToken = vi.fn(() => "issued-despite-audit-failure");

    const basicCredentials = Buffer.from(`${client.clientId}:client-secret`).toString(
      "base64"
    );
    const response = await new IssueTokenUseCase(ports).execute({
      method: "POST",
      baseUrl,
      requestUrl: `${baseUrl}/oauth2/v1/token`,
      headers: { authorization: `Basic ${basicCredentials}` },
      parameters: {
        grant_type: "client_credentials",
        scope: "openid"
      }
    });

    expect(response).toMatchObject({
      status: 200,
      body: {
        access_token: "issued-despite-audit-failure",
        token_type: "Bearer"
      }
    });
    expect(ports.tokens.saveTokens).toHaveBeenCalled();
    expect(ports.audit.record).toHaveBeenCalled();
  });
});

function oauthClient(overrides: Partial<OAuthClient> = {}): OAuthClient {
  return {
    clientId: "test-oauth-client",
    clientName: "Test OAuth Client",
    type: "public",
    redirectUris: ["https://app.example.com/callback"],
    scopes: ["openid", "profile"],
    grantTypes: [],
    authMethods: ["none"],
    opaqueToken: true,
    ...overrides
  };
}
