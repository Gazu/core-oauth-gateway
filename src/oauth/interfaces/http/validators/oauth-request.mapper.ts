import type { NextRequest } from "next/server";
import type {
  OAuthParameters,
  OAuthRequestDto
} from "@/oauth/application/dto/oauth-request.dto";
import {
  baseUrlFromRequest,
  paramsToRecord,
  readForm,
  readJson
} from "@/oauth/http";

export function queryRequest(request: NextRequest): OAuthRequestDto {
  return createRequest(request, paramsToRecord(request.nextUrl.searchParams));
}

export async function formRequest(request: NextRequest): Promise<OAuthRequestDto> {
  return createRequest(request, paramsToRecord(await readForm(request)));
}

export async function jsonRequest<TBody extends Record<string, unknown>>(
  request: NextRequest
): Promise<OAuthRequestDto<TBody | null>> {
  return {
    ...createRequest(request, paramsToRecord(request.nextUrl.searchParams)),
    body: await readJson<TBody>(request)
  };
}

export async function userInfoRequest(request: NextRequest): Promise<OAuthRequestDto> {
  const dto = request.method === "POST" ? await formRequest(request) : queryRequest(request);
  const authorization = request.headers.get("authorization");
  const bearer = authorization?.toLowerCase().startsWith("bearer ")
    ? authorization.slice("Bearer ".length).trim()
    : undefined;

  return {
    ...dto,
    parameters: {
      ...dto.parameters,
      ...(bearer ? { access_token: bearer } : {})
    }
  };
}

function createRequest(
  request: NextRequest,
  parameters: OAuthParameters
): OAuthRequestDto {
  return {
    method: request.method,
    baseUrl: baseUrlFromRequest(request),
    requestUrl: request.nextUrl.origin + request.nextUrl.pathname,
    headers: Object.fromEntries(request.headers.entries()),
    parameters
  };
}
