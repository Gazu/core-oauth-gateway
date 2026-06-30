import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const projectRoot = resolve(import.meta.dirname, "../..");
const appRoot = join(projectRoot, "src", "app");

const routeContracts = {
  "/.well-known/oauth-authorization-server": ["GET"],
  "/.well-known/openid-configuration": ["GET"],
  "/health": ["GET"],
  "/info": ["GET"],
  "/oauth2/v1/authdetails": ["POST"],
  "/oauth2/v1/authorize/par": ["POST"],
  "/oauth2/v1/authorize": ["GET"],
  "/oauth2/v1/certs": ["GET"],
  "/oauth2/v1/consent": ["GET"],
  "/oauth2/v1/introspect": ["POST"],
  "/oauth2/v1/listAccessTokens": ["POST"],
  "/oauth2/v1/revoke": ["POST"],
  "/oauth2/v1/revokeById": ["POST"],
  "/oauth2/v1/revokeBySID": ["POST"],
  "/oauth2/v1/token": ["POST"],
  "/oauth2/v1/tokeninfo": ["POST"],
  "/oauth2/v1/userauthorize": ["POST"],
  "/oauth2/v1/usererror": ["POST"],
  "/oauth2/v1/userinfo": ["GET", "POST"]
} as const;

describe("public route contracts", () => {
  for (const [route, methods] of Object.entries(routeContracts)) {
    it(`${route} exports only its supported HTTP methods`, () => {
      const source = readFileSync(join(appRoot, route.slice(1), "route.ts"), "utf8");
      const exportedMethods = [...source.matchAll(/export function (GET|POST|PUT|PATCH|DELETE|OPTIONS)/g)]
        .map((match) => match[1]);

      expect(exportedMethods).toEqual(methods);
      expect(source).toContain('export const runtime = "nodejs"');
      expect(source).toContain('export const dynamic = "force-dynamic"');
    });
  }
});
