import type { OAuthMaintenancePort } from "@/oauth/application/ports/oauth-application.ports";
import type { OAuthStateRepositoryPort } from "@/oauth/application/ports/oauth-state.repository.port";
import type { TokenRepositoryPort } from "@/oauth/application/ports/token.repository.port";

export class OAuthMaintenanceAdapter implements OAuthMaintenancePort {
  constructor(
    private readonly state: OAuthStateRepositoryPort,
    private readonly tokens: TokenRepositoryPort
  ) {}

  async cleanup(now = Date.now()): Promise<void> {
    await this.state.refresh(now);
    await this.tokens.cleanup(now);
    await this.state.cleanupTransient(now);
  }
}
