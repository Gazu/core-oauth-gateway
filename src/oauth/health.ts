import { jsonResponse } from "./http";
import { requireSupabaseRuntime, supabaseHeaders, supabaseRestUrl } from "./infrastructure/supabase";

type HealthBody = {
  status: "ok" | "error";
  service: "core-oauth-gateway";
  checks: {
    supabase: {
      status: "ok" | "error";
      latency_ms?: number;
      error?: string;
    };
  };
};

export async function healthHandler(): Promise<Response> {
  const startedAt = Date.now();

  try {
    requireSupabaseRuntime();
    const url = supabaseRestUrl("oauth_clients");
    url.searchParams.set("select", "client_id");
    url.searchParams.set("limit", "1");

    const response = await fetch(url, {
      headers: supabaseHeaders(),
      cache: "no-store"
    });
    const latencyMs = Date.now() - startedAt;

    if (!response.ok) {
      return jsonResponse(
        healthError(`Supabase query failed with status ${response.status}`, latencyMs),
        { status: 503 }
      );
    }

    return jsonResponse({
      status: "ok",
      service: "core-oauth-gateway",
      checks: {
        supabase: {
          status: "ok",
          latency_ms: latencyMs,
        }
      }
    } satisfies HealthBody);
  } catch (error) {
    return jsonResponse(
      healthError(error instanceof Error ? error.message : "Supabase health check failed", Date.now() - startedAt),
      { status: 503 }
    );
  }
}

function healthError(message: string, latencyMs: number): HealthBody {
  return {
    status: "error",
    service: "core-oauth-gateway",
    checks: {
      supabase: {
        status: "error",
        latency_ms: latencyMs,
        error: message
      }
    }
  };
}
