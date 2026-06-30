import { jsonResult, type OAuthResponseDto } from "../dto/oauth-response.dto";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

type HealthBody = {
  status: "ok" | "error";
  service: "core-oauth-gateway";
  checks: {
    supabase: {
      status: "ok" | "error";
      latency_ms: number;
      error?: string;
    };
  };
};

export class HealthCheckUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(): Promise<OAuthResponseDto> {
    const result = await this.ports.health.check();
    if (!result.ok) return this.healthError(result.error, result.latencyMs);

    return jsonResult({
      status: "ok",
      service: "core-oauth-gateway",
      checks: {
        supabase: { status: "ok", latency_ms: result.latencyMs }
      }
    } satisfies HealthBody);
  }

  private healthError(message: string, latencyMs: number): OAuthResponseDto {
    this.ports.loggers.oauth.error(message, {
      check: "supabase",
      tags: ["health", "supabase", "error"]
    });
    return jsonResult(
      {
        status: "error",
        service: "core-oauth-gateway",
        checks: {
          supabase: {
            status: "error",
            latency_ms: latencyMs,
            error: message
          }
        }
      } satisfies HealthBody,
      { status: 503 }
    );
  }
}
