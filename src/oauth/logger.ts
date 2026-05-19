import { LoggerConfiguration } from "@smb-tech/logger-core";
import {
  getNextTraceResponseHeaders,
  NodeLogger,
  NodeLogSink,
  RequestContextStore,
  withNextRequestContext
} from "@smb-tech/logger-node";
import type { NextRequest } from "next/server";
import { tokenHash } from "./jwt";

type Handler = (request: NextRequest) => Promise<Response>;

function ensureLoggerInitialized(): void {
  LoggerConfiguration.configure({
    level: process.env.LOG_LEVEL ?? "INFO",
    sampleRate: Number(process.env.LOGGER_SAMPLE_RATE ?? 1),
    sensitiveKeys: [
      "authorization",
      "cookie",
      "password",
      "secret",
      "token",
      "access_token",
      "refresh_token",
      "client_assertion",
      "assertion",
      "private_key",
      "encrypted_token"
    ],
    errorStackEnabled: process.env.LOGGER_ERROR_STACK_ENABLED === "true"
  });

  if (!NodeLogSink.isInitialized()) {
    NodeLogSink.initialize({
      mode: process.env.LOGGER_MODE === "sync" ? "sync" : "async",
      flushIntervalMs: Number(process.env.LOGGER_FLUSH_INTERVAL_MS ?? 10),
      maxQueueSize: Number(process.env.LOGGER_MAX_QUEUE_SIZE ?? 10000),
      overflowStrategy: process.env.LOGGER_OVERFLOW_STRATEGY === "drop" ? "drop" : "sync-fallback",
      shutdownTimeoutMs: Number(process.env.LOGGER_SHUTDOWN_TIMEOUT_MS ?? 2000),
      metricsEnabled: process.env.LOGGER_INTERNAL_METRICS_ENABLED === "true"
    });
  }
}

ensureLoggerInitialized();

export const oauthLogger = NodeLogger.get("OAuthServer");
export const tokenLogger = NodeLogger.get("OAuthToken");
export const clientAuthLogger = NodeLogger.get("OAuthClientAuth");
export const signingKeyLogger = NodeLogger.get("OAuthSigningKeys");
export const storeLogger = NodeLogger.get("OAuthStore");

export function withOAuthRequestLogging(handlerName: string, handler: Handler): Handler {
  return async (request: NextRequest): Promise<Response> => {
    ensureLoggerInitialized();
    const startedAt = Date.now();
    return withNextRequestContext(request, async () => {
      RequestContextStore.setManyMdc({
        handler: handlerName,
        method: request.method,
        path: request.nextUrl.pathname
      });

      oauthLogger.info((event) => {
        event
          .message("OAuth request started")
          .tag("oauth")
          .tag("http")
          .with("handler", handlerName)
          .with("method", request.method)
          .with("path", request.nextUrl.pathname);
      });

      try {
        const response = await handler(request);
        const durationMs = Date.now() - startedAt;
        oauthLogger.info((event) => {
          event
            .message("OAuth request completed")
            .tag("oauth")
            .tag("http")
            .with("handler", handlerName)
            .with("method", request.method)
            .with("path", request.nextUrl.pathname)
            .with("status", response.status)
            .with("durationMs", durationMs);
        });
        return withTraceHeaders(response);
      } catch (error) {
        const durationMs = Date.now() - startedAt;
        oauthLogger.error((event) => {
          event
            .message("OAuth request failed")
            .tag("oauth")
            .tag("http")
            .with("handler", handlerName)
            .with("method", request.method)
            .with("path", request.nextUrl.pathname)
            .with("durationMs", durationMs)
            .error(error);
        });
        throw error;
      }
    });
  };
}

export function tokenFingerprint(token: string | null | undefined): string | undefined {
  return token ? tokenHash(token) : undefined;
}

function withTraceHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  const traceHeaders = getNextTraceResponseHeaders();
  for (const [key, value] of Object.entries(traceHeaders)) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
