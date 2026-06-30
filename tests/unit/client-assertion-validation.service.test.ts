import { beforeEach, describe, expect, it, vi } from "vitest";
import { ClientAssertionValidationService } from "../../src/oauth/application/services/client-assertion-validation.service";
import type { OAuthApplicationPorts } from "../../src/oauth/application/ports/oauth-application.ports";
import type { OAuthClient } from "../../src/oauth/domain/entities/oauth-client";
import { createTestOAuthPorts } from "./helpers/oauth-ports";

const assertion = "header.payload.signature";
const audience = "https://oauth.example.com/oauth2/v1/token";
const client: OAuthClient = {
  clientId: "client-id",
  clientName: "Test client",
  type: "confidential",
  redirectUris: [],
  scopes: ["openid"],
  grantTypes: ["client_credentials"],
  authMethods: ["private_key_jwt"],
  jwks: {
    keys: [{ kty: "RSA", kid: "client-key", alg: "RS256", use: "sig" }]
  }
};

describe("ClientAssertionValidationService", () => {
  let ports: OAuthApplicationPorts;
  let service: ClientAssertionValidationService;

  beforeEach(() => {
    ports = createTestOAuthPorts();
    service = new ClientAssertionValidationService(ports);
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256", kid: "client-key" }));
    vi.mocked(ports.jwt.decode).mockReturnValue({
      iss: client.clientId,
      sub: client.clientId,
      aud: audience,
      exp: 1_800_000_300,
      jti: "assertion-jti"
    });
    ports.jwt.normalizeAudience = vi.fn(() => [audience]);
    ports.state.lookupClient = vi.fn(() => ({ status: "active" as const, client }));
    ports.remoteJwks.resolve = vi.fn(async () => client.jwks ?? null);
    ports.jwt.verifySignature = vi.fn(() => true);
    ports.replay.remember = vi.fn(async () => true);
  });

  it("returns the validated client, header and payload", async () => {
    const result = await validate(service);

    expect(result).toMatchObject({
      valid: true,
      client,
      header: { alg: "RS256", kid: "client-key" },
      payload: { iss: client.clientId, jti: "assertion-jti" }
    });
  });

  it("distinguishes an expired assertion", async () => {
    ports.jwt.isExpired = vi.fn(() => true);

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "assertion_expired",
      clientId: client.clientId
    });
    expect(ports.state.lookupClient).not.toHaveBeenCalled();
  });

  it("distinguishes a malformed compact JWT", async () => {
    const result = await service.validate({
      assertion: "not-a-jwt",
      acceptedAudiences: [audience]
    });

    expect(result).toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "jwt_malformed",
      clientId: undefined
    });
    expect(ports.jwt.decodeHeader).not.toHaveBeenCalled();
  });

  it("distinguishes a JWT header that cannot be decoded", async () => {
    ports.jwt.decodeHeader = vi.fn(() => null);

    await expect(validate(service)).resolves.toMatchObject({
      valid: false,
      rootCauseCode: "jwt_header_missing"
    });
  });

  it("distinguishes a signing algorithm that is not allowed", async () => {
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "HS256", kid: "client-key" }));

    await expect(validate(service)).resolves.toMatchObject({
      valid: false,
      rootCauseCode: "signing_algorithm_not_allowed"
    });
    expect(ports.jwt.decode).not.toHaveBeenCalled();
  });

  it("distinguishes a JWT payload that cannot be decoded", async () => {
    vi.mocked(ports.jwt.decode).mockReturnValue(null);

    await expect(validate(service)).resolves.toMatchObject({
      valid: false,
      rootCauseCode: "jwt_payload_invalid"
    });
  });

  it("distinguishes a missing issuer", async () => {
    vi.mocked(ports.jwt.decode).mockReturnValue({
      sub: client.clientId,
      aud: audience,
      exp: 1_800_000_300,
      jti: "assertion-jti"
    });

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "issuer_missing",
      clientId: undefined
    });
  });

  it("distinguishes an invalid audience", async () => {
    ports.jwt.normalizeAudience = vi.fn(() => ["https://attacker.example/token"]);

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "audience_invalid",
      clientId: client.clientId
    });
    expect(ports.state.lookupClient).not.toHaveBeenCalled();
  });

  it("distinguishes a client that no longer exists", async () => {
    ports.state.lookupClient = vi.fn(() => ({ status: "not_found" as const }));

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "unknown_client",
      rootCauseCode: "client_record_not_found",
      clientId: client.clientId
    });
  });

  it("distinguishes an inactive client", async () => {
    ports.state.lookupClient = vi.fn(() => ({ status: "inactive" as const, client }));

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "client_inactive",
      clientId: client.clientId
    });
  });

  it("distinguishes a client that does not allow private_key_jwt", async () => {
    const disallowedClient = {
      ...client,
      authMethods: ["client_secret_basic"]
    };
    ports.state.lookupClient = vi.fn(() => ({
      status: "active" as const,
      client: disallowedClient
    }));

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "authentication_method_not_allowed",
      clientId: client.clientId
    });
  });

  it("distinguishes an expected client id mismatch", async () => {
    const result = await service.validate({
      assertion,
      acceptedAudiences: [audience],
      expectedClientId: "different-client",
      requireClientSubject: true
    });

    expect(result).toEqual({
      valid: false,
      reasonCode: "client_id_mismatch",
      rootCauseCode: "client_id_mismatch",
      clientId: client.clientId
    });
  });

  it("distinguishes an issuer and subject mismatch", async () => {
    vi.mocked(ports.jwt.decode).mockReturnValue({
      iss: client.clientId,
      sub: "different-client",
      aud: audience,
      exp: 1_800_000_300,
      jti: "assertion-jti"
    });

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "issuer_subject_mismatch",
      clientId: client.clientId
    });
  });

  it("distinguishes a client without public verification material", async () => {
    const clientWithoutKey = { ...client, jwks: undefined, jwksUri: undefined };
    ports.state.lookupClient = vi.fn(() => ({
      status: "active" as const,
      client: clientWithoutKey
    }));

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "public_key_not_configured",
      clientId: client.clientId
    });
    expect(ports.remoteJwks.resolve).not.toHaveBeenCalled();
  });

  it("distinguishes a JWKS resolution failure", async () => {
    ports.remoteJwks.resolve = vi.fn(async () => null);

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "jwks_resolution_failed",
      clientId: client.clientId
    });
  });

  it("distinguishes a kid that is not present in the client JWKS", async () => {
    ports.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256", kid: "retired-key" }));

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "kid_not_found",
      clientId: client.clientId
    });
    expect(ports.jwt.verifySignature).not.toHaveBeenCalled();
  });

  it("distinguishes an invalid signature", async () => {
    ports.jwt.verifySignature = vi.fn(() => false);

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "signature_invalid",
      clientId: client.clientId
    });
  });

  it("distinguishes an assertion replay", async () => {
    ports.replay.remember = vi.fn(async () => false);

    await expect(validate(service)).resolves.toEqual({
      valid: false,
      reasonCode: "client_assertion_replay",
      rootCauseCode: "jti_already_registered",
      clientId: client.clientId
    });
  });

  it("can defer replay consumption until authorization checks finish", async () => {
    const result = await service.validate({
      assertion,
      acceptedAudiences: [audience],
      requireClientSubject: true,
      consumeReplay: false
    });

    expect(result.valid).toBe(true);
    expect(ports.replay.remember).not.toHaveBeenCalled();
    if (!result.valid) throw new Error("Expected a valid assertion");

    await expect(service.rememberReplay(result.client, result.payload)).resolves.toBeNull();
    expect(ports.replay.remember).toHaveBeenCalledWith(
      client.clientId,
      "assertion-jti",
      1_800_000_300
    );
  });

  it.each([
    {
      name: "missing kid",
      prepare: (testPorts: OAuthApplicationPorts) => {
        testPorts.jwt.decodeHeader = vi.fn(() => ({ alg: "RS256" }));
      },
      rootCauseCode: "kid_missing"
    },
    {
      name: "missing expiration",
      prepare: (testPorts: OAuthApplicationPorts) => {
        vi.mocked(testPorts.jwt.decode).mockReturnValue({
          iss: client.clientId,
          sub: client.clientId,
          aud: audience,
          jti: "assertion-jti"
        });
      },
      rootCauseCode: "expiration_missing"
    },
    {
      name: "missing audience",
      prepare: (testPorts: OAuthApplicationPorts) => {
        testPorts.jwt.normalizeAudience = vi.fn(() => []);
      },
      rootCauseCode: "audience_missing"
    },
    {
      name: "missing jti",
      prepare: (testPorts: OAuthApplicationPorts) => {
        vi.mocked(testPorts.jwt.decode).mockReturnValue({
          iss: client.clientId,
          sub: client.clientId,
          aud: audience,
          exp: 1_800_000_300
        });
      },
      rootCauseCode: "jti_missing"
    }
  ])("classifies $name independently", async ({ prepare, rootCauseCode }) => {
    prepare(ports);

    await expect(validate(service)).resolves.toMatchObject({
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode
    });
  });
});

function validate(service: ClientAssertionValidationService) {
  return service.validate({
    assertion,
    acceptedAudiences: [audience],
    requireClientSubject: true
  });
}
