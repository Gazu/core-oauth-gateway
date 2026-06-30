import type {
  HealthCheckPort,
  HealthCheckResult
} from "@/oauth/application/ports/observability.ports";
import {
  requireSupabaseRuntime,
  supabaseHeaders,
  supabaseRestUrl
} from "@/oauth/infrastructure/supabase";

export class SupabaseHealthAdapter implements HealthCheckPort {
  async check(): Promise<HealthCheckResult> {
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
          return fetch(url, { headers: supabaseHeaders(), cache: "no-store" });
        })
      );
      const failedIndex = responses.findIndex((response) => !response.ok);
      if (failedIndex >= 0) {
        throw new Error(
          `Supabase ${resources[failedIndex].table} query failed with status ${responses[failedIndex].status}`
        );
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (error) {
      return {
        ok: false,
        latencyMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : "Supabase health check failed"
      };
    }
  }
}
