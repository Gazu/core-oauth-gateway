import type { OAuthResponseDto } from "@/oauth/application/dto/oauth-response.dto";
import { emptyResponse, jsonResponse, oauthError } from "@/oauth/http";
import { oauthLogger } from "@/oauth/logger";

export function presentOAuthResponse(result: OAuthResponseDto): Response {
  if (result.errorLog) {
    oauthLogger.error(result.errorLog.description ?? result.errorLog.code, {
      error: result.errorLog.code,
      errorDescription: result.errorLog.description,
      status: result.status,
      errorUri: result.errorLog.uri,
      tags: ["oauth", "http", "redirect-error"]
    });
  }

  if (result.error) {
    return oauthError(result.error.code, result.error.description, {
      status: result.status,
      errorUri: result.error.uri,
      headers: result.headers
    });
  }

  if (result.empty) {
    return emptyResponse({ status: result.status, headers: result.headers });
  }

  return jsonResponse(result.body, {
    status: result.status,
    headers: result.headers
  });
}
