export interface ApplicationLoggerPort {
  debug(message: string, metadata?: Record<string, unknown>): void;
  info(message: string, metadata?: Record<string, unknown>): void;
  warn(message: string, metadata?: Record<string, unknown>): void;
  error(message: string, metadata?: Record<string, unknown>): void;
}

export type OAuthLoggersPort = {
  oauth: ApplicationLoggerPort;
  token: ApplicationLoggerPort;
  clientAuth: ApplicationLoggerPort;
};

export type HealthCheckResult =
  | { ok: true; latencyMs: number }
  | { ok: false; latencyMs: number; error: string };

export interface HealthCheckPort {
  check(): Promise<HealthCheckResult>;
}
