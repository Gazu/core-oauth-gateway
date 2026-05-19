import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "crypto";
import {
  RFC6749_AUTH_ERROR_URI,
  RFC6749_TOKEN_ERROR_URI
} from "./config";

type HeadersInput = HeadersInit | undefined;

export function baseUrlFromRequest(request: NextRequest): string {
  const forwardedHost = request.headers.get("x-forwarded-host");
  const forwardedProto = request.headers.get("x-forwarded-proto");
  const url = new URL(request.url);
  const host = forwardedHost ?? url.host;
  const protocol = forwardedProto ?? url.protocol.replace(":", "");

  return `${protocol}://${host}`;
}

export function oauthHeaders(headers?: HeadersInput): Headers {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Cache-Control", "no-store");
  responseHeaders.set("Pragma", "no-cache");
  responseHeaders.set("Gazu-OAuth-Request-Id", randomUUID());
  return responseHeaders;
}

export function jsonResponse(
  body: unknown,
  init?: {
    status?: number;
    headers?: HeadersInput;
  }
): NextResponse {
  return NextResponse.json(body, {
    status: init?.status ?? 200,
    headers: oauthHeaders(init?.headers)
  });
}

export function emptyResponse(
  init?: {
    status?: number;
    headers?: HeadersInput;
  }
): NextResponse {
  return new NextResponse(null, {
    status: init?.status ?? 200,
    headers: oauthHeaders(init?.headers)
  });
}

export function oauthError(
  error: string,
  description?: string,
  init?: {
    status?: number;
    errorUri?: string | null;
    headers?: HeadersInput;
  }
): NextResponse {
  const body: Record<string, string> = { error };
  if (description) body.error_description = description;
  if (init?.errorUri) body.error_uri = init.errorUri;

  return jsonResponse(body, {
    status: init?.status ?? 400,
    headers: init?.headers
  });
}

export function springParameterError(
  parameter: string,
  init?: {
    status?: number;
    authEndpoint?: boolean;
    headers?: HeadersInput;
  }
): NextResponse {
  return oauthError("invalid_request", `OAuth 2.0 Parameter: ${parameter}`, {
    status: init?.status ?? 400,
    errorUri: init?.authEndpoint ? RFC6749_AUTH_ERROR_URI : RFC6749_TOKEN_ERROR_URI,
    headers: init?.headers
  });
}

export function invalidClient(description = "Client authentication failed"): NextResponse {
  return oauthError("invalid_client", description, {
    status: 401,
    errorUri: RFC6749_TOKEN_ERROR_URI,
    headers: {
      "WWW-Authenticate": `Basic realm="core-oauth-gateway", error="invalid_client", error_description="${description}"`
    }
  });
}

export async function readForm(request: NextRequest): Promise<URLSearchParams> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return request.nextUrl.searchParams.size > 0
      ? mergeParams(new URLSearchParams(await request.text()), request.nextUrl.searchParams)
      : new URLSearchParams(await request.text());
  }

  if (contentType.includes("multipart/form-data")) {
    const data = await request.formData();
    const params = new URLSearchParams();
    for (const [key, value] of data.entries()) {
      if (typeof value === "string") params.append(key, value);
    }
    return params;
  }

  const text = await request.text();
  return text ? new URLSearchParams(text) : new URLSearchParams();
}

export async function readJson<T extends Record<string, unknown>>(
  request: NextRequest
): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

export function paramsToRecord(params: URLSearchParams): Record<string, string> {
  const record: Record<string, string> = {};
  for (const [key, value] of params.entries()) {
    record[key] = value;
  }
  return record;
}

export function redirectWithOAuthError(
  redirectUri: string,
  error: string,
  description?: string,
  state?: string,
  errorUri = RFC6749_AUTH_ERROR_URI
): NextResponse {
  const location = new URL(redirectUri);
  location.searchParams.set("error", error);
  if (description) location.searchParams.set("error_description", description);
  if (errorUri) location.searchParams.set("error_uri", errorUri);
  if (state) location.searchParams.set("state", state);

  return emptyResponse({
    status: 302,
    headers: {
      Location: location.toString()
    }
  });
}

function mergeParams(primary: URLSearchParams, fallback: URLSearchParams): URLSearchParams {
  const merged = new URLSearchParams(primary);
  for (const [key, value] of fallback.entries()) {
    if (!merged.has(key)) merged.set(key, value);
  }
  return merged;
}
