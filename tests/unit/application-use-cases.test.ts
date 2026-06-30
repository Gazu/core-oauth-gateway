import { describe, expect, it, vi } from "vitest";
import { jsonResult } from "../../src/oauth/application/dto/oauth-response.dto";
import type { OAuthRequestDto } from "../../src/oauth/application/dto/oauth-request.dto";
import type {
  TokenGrantContext,
  TokenGrantStrategy
} from "../../src/oauth/application/services/grants/token-grant.strategy";
import { IssueTokenUseCase } from "../../src/oauth/application/use-cases/issue-token-use-case";
import { GetDiscoveryDocumentUseCase } from "../../src/oauth/application/use-cases/discovery-use-cases";
import { GetServiceInfoUseCase } from "../../src/oauth/application/use-cases/get-service-info-use-case";
import { createTestOAuthPorts } from "./helpers/oauth-ports";

const request = {
  method: "POST",
  baseUrl: "https://oauth.example.com",
  requestUrl: "https://oauth.example.com/oauth2/v1/token",
  headers: {},
  parameters: { grant_type: "test_grant" }
} satisfies OAuthRequestDto;

describe("application use cases", () => {
  it("dispatches token grants through a framework-independent strategy", async () => {
    const execute = vi.fn(async (context: TokenGrantContext) => {
      void context;
      return jsonResult({ issued: true });
    });
    const strategy: TokenGrantStrategy = {
      grantTypes: ["test_grant"],
      execute
    };
    const cleanup = vi.fn(async () => undefined);
    const ports = createTestOAuthPorts({ maintenance: { cleanup } });
    const useCase = new IssueTokenUseCase(ports, [strategy]);

    const result = await useCase.execute(request);

    expect(result).toEqual({ status: 200, body: { issued: true }, headers: undefined });
    expect(cleanup).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledWith({
      request,
      oauthFlowId: expect.any(String)
    });
  });

  it("returns the OAuth unsupported_grant_type contract", async () => {
    const useCase = new IssueTokenUseCase(createTestOAuthPorts(), []);
    const result = await useCase.execute(request);

    expect(result).toMatchObject({
      status: 400,
      error: {
        code: "unsupported_grant_type",
        description: "OAuth 2.0 Parameter: grant_type"
      }
    });
  });

  it("builds discovery data without HTTP framework types", () => {
    const result = new GetDiscoveryDocumentUseCase(createTestOAuthPorts()).execute(
      request.baseUrl
    );
    expect(result).toMatchObject({
      status: 200,
      body: {
        issuer: request.baseUrl,
        token_endpoint: `${request.baseUrl}/oauth2/v1/token`
      }
    });
  });

  it("returns service metadata without HTTP framework types", () => {
    const result = new GetServiceInfoUseCase({
      service_name: "core-oauth-gateway",
      service_version: "0.2.0",
      environment: "test"
    }).execute();

    expect(result).toEqual({
      service_name: "core-oauth-gateway",
      service_version: "0.2.0",
      environment: "test"
    });
  });
});
