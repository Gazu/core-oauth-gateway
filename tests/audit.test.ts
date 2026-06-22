import { runWithTraceContext, type Logger } from "@smb-tech/service-framework-js";
import { describe, expect, it, vi } from "vitest";
import {
  OAuthAuditService,
  auditHash,
  type AuditEvent
} from "../src/oauth/audit";

const traceContext = {
  requestId: "7d3f9dc7-cbe2-4ec2-8fb8-0065aad538c8",
  traceId: "4d521de94ce7dccca3720118022ca6a8",
  spanId: "0123456789abcdef"
};
const oauthFlowId = "89089f1e-7aed-48ec-9b08-a3147ee594ae";
const auditId = "2bc8457d-d1b6-44b2-adae-6610a43b6fb6";

function loggerSpies(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

describe("OAuthAuditService", () => {
  it("persists a correlated event and logs STARTED followed by SUCCESS", async () => {
    const logger = loggerSpies();
    const persisted: AuditEvent[] = [];
    const service = new OAuthAuditService({
      logger,
      persist: async (event) => {
        persisted.push(event);
      },
      idFactory: () => auditId,
      now: () => new Date("2026-06-22T14:46:39.071Z")
    });

    const result = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "tokens_issued",
        auditStatus: "SUCCESS",
        oauthFlowId,
        details: {
          grantType: "authorization_code",
          accessTokenHash: "sha256:access"
        }
      })
    );

    expect(result).toEqual({
      auditId,
      auditType: "tokens_issued",
      auditStatus: "SUCCESS",
      oauthFlowId,
      persisted: true,
      persistenceSkipped: false
    });
    expect(persisted).toEqual([
      {
        auditId,
        auditType: "tokens_issued",
        auditStatus: "SUCCESS",
        requestId: traceContext.requestId,
        traceId: traceContext.traceId,
        spanId: traceContext.spanId,
        oauthFlowId,
        eventTimestamp: "2026-06-22T14:46:39.071Z",
        grantType: "authorization_code",
        accessTokenHash: "sha256:access"
      }
    ]);
    expect(logger.info).toHaveBeenNthCalledWith(
      1,
      "Audit event started",
      expect.objectContaining({ auditStatus: "STARTED", oauthFlowId })
    );
    expect(logger.info).toHaveBeenNthCalledWith(
      2,
      "Audit event completed",
      expect.objectContaining({ auditStatus: "SUCCESS", auditId, oauthFlowId })
    );
  });

  it("absorbs persistence failures and emits an ERROR audit lifecycle log", async () => {
    const logger = loggerSpies();
    const service = new OAuthAuditService({
      logger,
      persist: async () => {
        throw new Error("database unavailable");
      },
      idFactory: () => auditId
    });

    const result = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "token_revoked",
        auditStatus: "SUCCESS",
        oauthFlowId,
        details: { tokenHash: "sha256:revoked" }
      })
    );

    expect(result.persisted).toBe(false);
    expect(result.failureReasonCode).toBe("audit_persistence_failed");
    expect(logger.error).toHaveBeenCalledWith(
      "Audit event failed",
      expect.objectContaining({
        auditStatus: "FAILURE",
        expectedAuditEvent: "token_revoked",
        reasonCode: "audit_persistence_failed"
      })
    );
  });

  it("rejects non-serializable details without throwing to the caller", async () => {
    const logger = loggerSpies();
    const persist = vi.fn(async () => undefined);
    const service = new OAuthAuditService({
      logger,
      persist,
      idFactory: () => auditId
    });

    const result = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "tokens_issued",
        auditStatus: "SUCCESS",
        oauthFlowId,
        details: { invalid: 1n }
      })
    );

    expect(result.persisted).toBe(false);
    expect(result.failureReasonCode).toBe("audit_serialization_failed");
    expect(persist).not.toHaveBeenCalled();
  });

  it("only exposes a prefixed SHA-256 fingerprint", () => {
    const rawToken = "do-not-log-this-token";
    const fingerprint = auditHash(rawToken);

    expect(fingerprint).toMatch(/^sha256:[A-Za-z0-9_-]{43}$/);
    expect(fingerprint).not.toContain(rawToken);
  });

  it("skips table writes when persistence is disabled", async () => {
    const logger = loggerSpies();
    const persist = vi.fn(async () => undefined);
    const service = new OAuthAuditService({
      logger,
      persist,
      persistenceMode: "disabled"
    });

    const result = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "tokens_issued",
        auditStatus: "SUCCESS",
        oauthFlowId
      })
    );

    expect(result.persisted).toBe(false);
    expect(result.persistenceSkipped).toBe(true);
    expect(persist).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenLastCalledWith(
      "Audit event completed",
      expect.objectContaining({
        persistenceMode: "disabled",
        persistenceSkipped: true
      })
    );
  });

  it("persists only FAILURE events in errors_only mode", async () => {
    const persist = vi.fn(async () => undefined);
    const service = new OAuthAuditService({
      logger: loggerSpies(),
      persist,
      persistenceMode: "errors_only"
    });

    const success = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "client_authenticated",
        auditStatus: "SUCCESS",
        oauthFlowId
      })
    );
    const failure = await runWithTraceContext(traceContext, () =>
      service.record({
        auditType: "client_authentication_failed",
        auditStatus: "FAILURE",
        oauthFlowId,
        details: { reasonCode: "invalid_client_assertion" }
      })
    );

    expect(success.persistenceSkipped).toBe(true);
    expect(failure.persisted).toBe(true);
    expect(failure.persistenceSkipped).toBe(false);
    expect(persist).toHaveBeenCalledTimes(1);
  });
});
