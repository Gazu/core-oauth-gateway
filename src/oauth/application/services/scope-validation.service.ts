import { evaluateRequestedScope } from "@/oauth/domain/scope-policy";
import type { OAuthClient } from "@/oauth/types";
import {
  oauthErrorResult,
  type OAuthResponseDto
} from "@/oauth/application/dto/oauth-response.dto";
import type { OAuthApplicationConfig } from "../ports/oauth-config.port";

export function normalizeRequestedScope(
  requestedScope: string | null | undefined,
  client: OAuthClient,
  config: Pick<OAuthApplicationConfig, "authorizationErrorUri" | "tokenErrorUri">,
  authEndpoint = false
):
  | { ok: true; value: string }
  | { ok: false; response: OAuthResponseDto } {
  const result = evaluateRequestedScope(requestedScope, client);
  if (result.ok) return result;

  return {
    ok: false,
    response: oauthErrorResult("invalid_scope", "OAuth 2.0 Parameter: scope", {
      errorUri: authEndpoint ? config.authorizationErrorUri : config.tokenErrorUri
    })
  };
}
