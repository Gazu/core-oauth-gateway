import type { AuditServicePort } from "./audit-service.port";
import type { JwtServicePort } from "./jwt-service.port";
import type { OAuthApplicationConfig } from "./oauth-config.port";
import type { OAuthStateRepositoryPort } from "./oauth-state.repository.port";
import type { HealthCheckPort, OAuthLoggersPort } from "./observability.ports";
import type {
  ClientAssertionReplayPort,
  ClientSecretVerifierPort,
  RemoteJwksPort
} from "./security.ports";
import type { TokenRepositoryPort } from "./token.repository.port";

export interface OAuthMaintenancePort {
  cleanup(now?: number): Promise<void>;
}

export type OAuthApplicationPorts = {
  state: OAuthStateRepositoryPort;
  tokens: TokenRepositoryPort;
  jwt: JwtServicePort;
  audit: AuditServicePort;
  replay: ClientAssertionReplayPort;
  clientSecrets: ClientSecretVerifierPort;
  remoteJwks: RemoteJwksPort;
  health: HealthCheckPort;
  loggers: OAuthLoggersPort;
  config: OAuthApplicationConfig;
  maintenance: OAuthMaintenancePort;
};
