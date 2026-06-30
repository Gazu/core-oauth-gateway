import {
  RFC6749_AUTH_ERROR_URI,
  RFC6749_TOKEN_ERROR_URI
} from "../../domain/value-objects/oauth-protocol";

export type OAuthResponseDto = {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  empty?: boolean;
  error?: {
    code: string;
    description?: string;
    uri?: string | null;
  };
  errorLog?: {
    code: string;
    description?: string;
    uri?: string | null;
  };
};

export function jsonResult(
  body: unknown,
  options: { status?: number; headers?: Record<string, string> } = {}
): OAuthResponseDto {
  return {
    status: options.status ?? 200,
    body,
    headers: options.headers
  };
}

export function emptyResult(
  options: { status?: number; headers?: Record<string, string> } = {}
): OAuthResponseDto {
  return {
    status: options.status ?? 200,
    headers: options.headers,
    empty: true
  };
}

export function oauthErrorResult(
  code: string,
  description?: string,
  options: {
    status?: number;
    errorUri?: string | null;
    headers?: Record<string, string>;
  } = {}
): OAuthResponseDto {
  return {
    status: options.status ?? 400,
    headers: options.headers,
    error: {
      code,
      description,
      uri: options.errorUri
    }
  };
}

export function springParameterErrorResult(
  parameter: string,
  options: { status?: number; authEndpoint?: boolean } = {}
): OAuthResponseDto {
  return oauthErrorResult("invalid_request", `OAuth 2.0 Parameter: ${parameter}`, {
    status: options.status ?? 400,
    errorUri: options.authEndpoint ? RFC6749_AUTH_ERROR_URI : RFC6749_TOKEN_ERROR_URI
  });
}

export function invalidClientResult(
  description = "Client authentication failed"
): OAuthResponseDto {
  return oauthErrorResult("invalid_client", description, {
    status: 401,
    errorUri: RFC6749_TOKEN_ERROR_URI,
    headers: {
      "WWW-Authenticate":
        `Basic realm="core-oauth-gateway", error="invalid_client", error_description="${description}"`
    }
  });
}

export function invalidJwtBearerAssertionResult(
  errorUri = RFC6749_TOKEN_ERROR_URI
): OAuthResponseDto {
  return oauthErrorResult(
    "invalid_grant",
    "OAuth 2.0 Parameter: assertion",
    { errorUri }
  );
}

export function redirectErrorResult(
  redirectUri: string,
  code: string,
  description?: string,
  state?: string,
  errorUri = RFC6749_AUTH_ERROR_URI
): OAuthResponseDto {
  const location = new URL(redirectUri);
  location.searchParams.set("error", code);
  if (description) location.searchParams.set("error_description", description);
  if (errorUri) location.searchParams.set("error_uri", errorUri);
  if (state) location.searchParams.set("state", state);

  return {
    ...emptyResult({
      status: 302,
      headers: { Location: location.toString() }
    }),
    errorLog: { code, description, uri: errorUri }
  };
}
