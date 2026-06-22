const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const EXPECTED_SUPABASE_ROLE = "service_role";

export function supabaseRestUrl(table: string): URL {
  return new URL(`/rest/v1/${table}`, normalizedSupabaseUrl());
}

export function supabaseRpcUrl(functionName: string): URL {
  return new URL(`/rest/v1/rpc/${functionName}`, normalizedSupabaseUrl());
}

export function supabaseHeaders(): HeadersInit {
  const key = serviceRoleKey();
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json"
  };
}

export function requireSupabaseRuntime(): void {
  normalizedSupabaseUrl();
  serviceRoleKey();
}

function normalizedSupabaseUrl(): string {
  if (!SUPABASE_URL) {
    throw new Error("SUPABASE_URL is required for production OAuth persistence");
  }
  return SUPABASE_URL.endsWith("/") ? SUPABASE_URL : `${SUPABASE_URL}/`;
}

function serviceRoleKey(): string {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY is required for production OAuth persistence");
  }
  assertSupabaseServiceRoleKey(SUPABASE_SERVICE_ROLE_KEY);
  return SUPABASE_SERVICE_ROLE_KEY;
}

function assertSupabaseServiceRoleKey(key: string): void {
  const role = decodeSupabaseJwtRole(key);
  if (role && role !== EXPECTED_SUPABASE_ROLE) {
    throw new Error(
      `SUPABASE_SERVICE_ROLE_KEY must be a Supabase service_role key, but received a key with role "${role}". ` +
        "Use Project Settings > API > service_role key on the server only."
    );
  }
}

function decodeSupabaseJwtRole(jwt: string): string | undefined {
  const payload = jwt.split(".")[1];
  if (!payload) return undefined;

  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { role?: unknown };
    return typeof decoded.role === "string" ? decoded.role : undefined;
  } catch {
    return undefined;
  }
}
