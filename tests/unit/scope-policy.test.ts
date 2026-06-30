import { describe, expect, it } from "vitest";
import { evaluateRequestedScope } from "../../src/oauth/domain/scope-policy";
import type { OAuthClient } from "../../src/oauth/types";

const client = {
  clientId: "test-client",
  clientName: "Test Client",
  type: "public",
  redirectUris: [],
  scopes: ["openid", "profile"],
  grantTypes: ["authorization_code"],
  authMethods: ["none"]
} satisfies OAuthClient;

describe("scope policy", () => {
  it("uses all configured client scopes when scope is omitted", () => {
    expect(evaluateRequestedScope(undefined, client)).toEqual({
      ok: true,
      value: "openid profile"
    });
  });

  it("rejects scopes outside the client allowlist", () => {
    expect(evaluateRequestedScope("openid admin", client)).toEqual({ ok: false });
  });
});
