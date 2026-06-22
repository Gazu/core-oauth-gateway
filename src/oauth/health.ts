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
    const resources = [
      { table: "oauth_clients", select: "client_id" },
      { table: "oauth_authentication_providers", select: "provider_id,login_url" }
    ];
    const responses = await Promise.all(
      resources.map(({ table, select }) => {
        const url = supabaseRestUrl(table);
        url.searchParams.set("select", select);
        url.searchParams.set("limit", "1");
        return fetch(url, {
          headers: supabaseHeaders(),
          cache: "no-store"
        });
      })
    );
    const latencyMs = Date.now() - startedAt;
    const failedIndex = responses.findIndex((response) => !response.ok);

    if (failedIndex >= 0) {
      return jsonResponse(
        healthError(
          `Supabase ${resources[failedIndex].table} query failed with status ${responses[failedIndex].status}`,
          latencyMs
        ),
        { status: 503 }
      );
    }

    return jsonResponse({
      status: "ok",
      service: "core-oauth-gateway",
      checks: {
        supabase: {
          status: "ok",
          latency_ms: latencyMs
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
