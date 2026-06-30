import { describe, expect, it } from "vitest";
import { createOAuthLogger } from "../../src/oauth/logger";

describe("framework logging", () => {
  it("redacts OAuth credentials and nested sensitive values", () => {
    const entries: Record<string, unknown>[] = [];
    const logger = createOAuthLogger(
      "SecurityTest",
      (_level, payload) => {
        entries.push(payload);
      }
    );

    logger.info("redaction contract", {
      password: "plain-password",
      access_token: "plain-access-token",
      nested: {
        cookie: "session-cookie",
        oauth_key_signature: "signed-assertion"
      },
      safe: "visible"
    });

    const serialized = JSON.stringify(entries);
    expect(serialized).toContain("visible");
    expect(serialized).toContain("[REDACTED]");
    expect(serialized).not.toContain("plain-password");
    expect(serialized).not.toContain("plain-access-token");
    expect(serialized).not.toContain("session-cookie");
    expect(serialized).not.toContain("signed-assertion");
  });
});
