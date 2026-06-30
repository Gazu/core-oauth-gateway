import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "crypto";
import { getCurrentTraceContext } from "@smb-tech/service-framework-js";
import { oauthLogger } from "./logger";

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
  responseHeaders.set(
    "Gazu-OAuth-Request-Id",
    getCurrentTraceContext()?.requestId ?? randomUUID()
  );
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

  oauthLogger.error(description ?? error, {
    error,
    errorDescription: description,
    status: init?.status ?? 400,
    errorUri: init?.errorUri,
    tags: ["oauth", "http", "error"]
  });

  return jsonResponse(body, {
    status: init?.status ?? 400,
    headers: init?.headers
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

function mergeParams(primary: URLSearchParams, fallback: URLSearchParams): URLSearchParams {
  const merged = new URLSearchParams(primary);
  for (const [key, value] of fallback.entries()) {
    if (!merged.has(key)) merged.set(key, value);
  }
  return merged;
}
