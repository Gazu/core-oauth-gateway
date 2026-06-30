import {
  DEFAULT_SENSITIVE_FIELDS,
  createLogger,
  createNextBffService,
  initializeSmbLogger,
  redactSensitiveData,
  type LogLevel,
  type Logger
} from "@smb-tech/service-framework-js";
import type { NextRequest } from "next/server";
import { tokenHash } from "./jwt";

type Handler = (request: NextRequest) => Promise<Response>;

const serviceName = process.env.SERVICE_NAME ?? "core-oauth-gateway";
const serviceVersion = process.env.SERVICE_VERSION ?? "0.1.0";
const sensitiveKeys = [
  ...DEFAULT_SENSITIVE_FIELDS,
  "oauth_key_signature",
  "user_jwt",
  "encrypted_token",
  "p12_password_base64"
];

const loggerInitialization = initializeSmbLogger({ sensitiveKeys });
export const oauthLogger = createOAuthLogger("OAuthServer");

const service = createNextBffService({
  env: {
    ...process.env,
    SERVICE_NAME: serviceName,
    SERVICE_VERSION: serviceVersion
  },
  logger: oauthLogger,
  requireBaseUrlOrTokenUrl: false,
  requireJwt: false,
  requireIssuer: false,
  requireAudience: false
});

export const tokenLogger = createOAuthLogger("OAuthToken");
export const clientAuthLogger = createOAuthLogger("OAuthClientAuth");
export const signingKeyLogger = createOAuthLogger("OAuthSigningKeys");
export const storeLogger = createOAuthLogger("OAuthStore");
export const auditLogger = createOAuthLogger("OAuthAuditService");

export function createOAuthLogger(
  contextName: string,
  writer?: (level: LogLevel, payload: Record<string, unknown>) => void
): Logger {
  const logger = createLogger({
    contextName,
    serviceName,
    useSmbLogger: !writer,
    writer
  });
  const secureMeta = (meta?: Record<string, unknown>) =>
    redactSensitiveData(meta ?? {}, { sensitiveFields: sensitiveKeys });

  return {
    debug: (message, meta) => logger.debug(message, secureMeta(meta)),
    info: (message, meta) => logger.info(message, secureMeta(meta)),
    warn: (message, meta) => logger.warn(message, secureMeta(meta)),
    error: (message, meta) => logger.error(message, secureMeta(meta))
  };
}

export function withOAuthRequestLogging(_handlerName: string, handler: Handler): Handler {
  return service.route(async (request) => {
    await loggerInitialization;
    try {
      return await handler(request as NextRequest);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unexpected OAuth error";
      oauthLogger.error(message, {
        tags: ["oauth", "http", "exception"],
        exception: error
      });
      throw error;
    }
  });
}

export function tokenFingerprint(token: string | null | undefined): string | undefined {
  return token ? tokenHash(token) : undefined;
}
