import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decodeJwt,
  decodeJwtHeader,
  signJwtWithKey,
  verifyJwtSignature
} from "../src/oauth/jwt";

describe("OAuth JWT compatibility", () => {
  it("preserves the header, claims and RS256 signature contract", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const kid = "test-signing-key";
    const payload = {
      iss: "http://localhost:3000",
      sub: "user-123",
      aud: "quickfade-bff-web",
      iat: 1_800_000_000,
      exp: 1_800_000_300,
      jti: "jwt-id",
      scope: "openid profile",
      client_id: "client-id",
      profile: { display_name: "Test User" },
      idt: { auth_time: 1_800_000_000 }
    };

    const jwt = signJwtWithKey(payload, { kid, privateKey });
    const publicJwk = publicKey.export({ format: "jwk" });

    expect(decodeJwtHeader(jwt)).toEqual({ typ: "JWT", alg: "RS256", kid });
    expect(decodeJwt(jwt)).toEqual(payload);
    expect(verifyJwtSignature(jwt, {
      keys: [{ ...publicJwk, kid, alg: "RS256", use: "sig" }]
    })).toBe(true);

    const [header, , signature] = jwt.split(".");
    const tamperedPayload = Buffer.from(JSON.stringify({ ...payload, sub: "attacker" }))
      .toString("base64url");
    expect(verifyJwtSignature(`${header}.${tamperedPayload}.${signature}`, {
      keys: [{ ...publicJwk, kid, alg: "RS256", use: "sig" }]
    })).toBe(false);
  });
});
