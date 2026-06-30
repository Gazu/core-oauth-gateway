import type { OAuthParameters } from "./value-objects/oauth-parameters";
import type { TokenClaims } from "../types";

export function required(params: OAuthParameters, key: string): string | null {
  const value = params[key];
  return value && value.trim() ? value : null;
}

export function optional(params: OAuthParameters, key: string): string | undefined {
  return params[key];
}

export function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function objectClaim(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function splitScope(scope: string): string[] {
  return scope
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function constrainUserScope(requestedScope: string, providerScope?: string): string {
  if (!providerScope) return requestedScope;
  const approved = new Set(splitScope(providerScope));
  return splitScope(requestedScope)
    .filter((scope) => approved.has(scope))
    .join(" ");
}

export function cleanCustomClaims(claims: TokenClaims): TokenClaims {
  const blocked = new Set(["iss", "aud", "exp", "iat", "jti", "nbf"]);
  return Object.fromEntries(Object.entries(claims).filter(([key]) => !blocked.has(key)));
}

export function introspectionCustomClaims(claims: TokenClaims): TokenClaims {
  const blocked = new Set([
    "active",
    "scope",
    "client_id",
    "username",
    "token_type",
    "exp",
    "iat",
    "nbf",
    "sub",
    "aud",
    "iss",
    "jti"
  ]);
  return Object.fromEntries(Object.entries(claims).filter(([key]) => !blocked.has(key)));
}

export function parseAuthorizationDetails(value: string | undefined): unknown {
  if (!value) return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

export function parseRequiredClaims(
  value: string | undefined
): Array<{ path: string[]; value: string }> {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [path, ...rest] = entry.split(":");
      return {
        path: path.split("~"),
        value: rest.join(":")
      };
    })
    .filter((entry) => entry.path.length > 0 && entry.value.length > 0);
}

export function claimsMatch(
  claims: TokenClaims,
  requiredClaims: Array<{ path: string[]; value: string }>
): boolean {
  return requiredClaims.every((claim) => {
    let current: unknown = claims;
    for (const segment of claim.path) {
      if (!current || typeof current !== "object" || Array.isArray(current)) return false;
      current = (current as Record<string, unknown>)[segment];
    }
    return String(current) === claim.value;
  });
}

export function addTokenDescriptor(
  response: Record<string, unknown[]>,
  clientId: string,
  descriptor: Record<string, unknown>
): void {
  if (!response[clientId]) response[clientId] = [];
  response[clientId].push(descriptor);
}
