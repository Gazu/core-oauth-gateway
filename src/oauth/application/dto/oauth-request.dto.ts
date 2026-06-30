import type { OAuthParameters } from "../../domain/value-objects/oauth-parameters";

export type { OAuthParameters } from "../../domain/value-objects/oauth-parameters";

export type OAuthRequestDto<TBody = unknown> = {
  method: string;
  baseUrl: string;
  requestUrl: string;
  headers: Record<string, string>;
  parameters: OAuthParameters;
  body?: TBody;
};
