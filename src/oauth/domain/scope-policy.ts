import type { OAuthClient } from "../types";
import { splitScope } from "./oauth-values";

export type ScopePolicyResult =
  | { ok: true; value: string }
  | { ok: false };

export function evaluateRequestedScope(
  requestedScope: string | null | undefined,
  client: OAuthClient
): ScopePolicyResult {
  const requested = splitScope(requestedScope ?? "");
  const effectiveScopes = requested.length ? requested : client.scopes;

  if (!effectiveScopes.length) {
    return { ok: false };
  }

  if (effectiveScopes.some((scope) => !client.scopes.includes(scope))) {
    return { ok: false };
  }

  return { ok: true, value: effectiveScopes.join(" ") };
}
