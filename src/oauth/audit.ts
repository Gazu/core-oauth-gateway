import { createHash, randomUUID } from "crypto";
import {
  getCurrentTraceContext,
  type Logger
} from "@smb-tech/service-framework-js";
import { supabaseHeaders, supabaseRestUrl } from "./infrastructure/supabase";
import { auditLogger } from "./logger";
import {
  isAuditRootCauseCode,
  type AuditRootCauseCode
} from "./domain/value-objects/audit-root-cause";

export const AUDIT_TYPES = [
  "authorization_requested",
  "authorization_failed",
  "user_authenticated",
  "authentication_failed",
  "authorization_code_issued",
  "tokens_issued",
  "refresh_token_used",
  "token_revoked",
  "client_authenticated",
  "client_authentication_failed"
] as const;

export const AUDIT_FAILURE_REASON_CODES = [
  "audit_generation_failed",
  "audit_serialization_failed",
  "audit_validation_failed",
  "audit_persistence_failed",
  "audit_publish_failed",
  "audit_dispatch_failed",
  "audit_timeout",
  "audit_unexpected_error"
] as const;

export type AuditType = (typeof AUDIT_TYPES)[number];
export type AuditStatus = "SUCCESS" | "FAILURE";
export type AuditFailureReasonCode = (typeof AUDIT_FAILURE_REASON_CODES)[number];
export type AuditPersistenceMode = "all" | "errors_only" | "disabled";

export type AuditEventInput = {
  auditType: AuditType;
  auditStatus: AuditStatus;
  oauthFlowId: string;
  reasonCode?: string;
  rootCauseCode?: AuditRootCauseCode;
  details?: Record<string, unknown>;
};

export type AuditEvent = Record<string, unknown> & {
  auditId: string;
  auditType: AuditType;
  auditStatus: AuditStatus;
  requestId: string;
  traceId: string;
  spanId: string;
  oauthFlowId: string;
  eventTimestamp: string;
  reasonCode?: string;
  rootCauseCode?: AuditRootCauseCode;
};

export type AuditResult = {
  auditId: string;
  auditType: AuditType;
  auditStatus: AuditStatus;
  oauthFlowId: string;
  persisted: boolean;
  persistenceSkipped?: boolean;
  failureReasonCode?: AuditFailureReasonCode;
};

export type AuditEventPersistenceRow = {
  audit_id: string;
  audit_type: AuditType;
  audit_status: AuditStatus;
  request_id: string;
  trace_id: string;
  span_id: string;
  oauth_flow_id: string;
  event_timestamp: string;
  reason_code: string | null;
  root_cause_code: AuditRootCauseCode | null;
  event_payload: AuditEvent;
};

type AuditServiceOptions = {
  logger?: Logger;
  persist?: (event: AuditEvent) => Promise<void>;
  idFactory?: () => string;
  now?: () => Date;
  persistenceMode?: string;
};

const RESERVED_EVENT_FIELDS = new Set([
  "auditId",
  "auditType",
  "auditStatus",
  "requestId",
  "traceId",
  "spanId",
  "oauthFlowId",
  "eventTimestamp",
  "reasonCode",
  "rootCauseCode"
]);
const AUDIT_TIMEOUT_MS = Number(process.env.OAUTH_AUDIT_TIMEOUT_MS ?? 2000);
const DEFAULT_AUDIT_PERSISTENCE_MODE =
  process.env.OAUTH_AUDIT_PERSISTENCE_MODE ?? "all";

class AuditFailure extends Error {
  constructor(
    readonly reasonCode: AuditFailureReasonCode,
    message: string
  ) {
    super(message);
  }
}

export class OAuthAuditService {
  private readonly logger: Logger;
  private readonly persist: (event: AuditEvent) => Promise<void>;
  private readonly idFactory: () => string;
  private readonly now: () => Date;
  private readonly persistenceMode: string;

  constructor(options: AuditServiceOptions = {}) {
    this.logger = options.logger ?? auditLogger;
    this.persist = options.persist ?? persistAuditEvent;
    this.idFactory = options.idFactory ?? randomUUID;
    this.now = options.now ?? (() => new Date());
    this.persistenceMode = options.persistenceMode ?? DEFAULT_AUDIT_PERSISTENCE_MODE;
  }

  async record(input: AuditEventInput): Promise<AuditResult> {
    const startedAt = Date.now();
    let auditId: string;
    let generationFailed = false;
    try {
      auditId = this.idFactory();
    } catch {
      auditId = randomUUID();
      generationFailed = true;
    }
    const correlation = {
      auditId,
      auditType: input.auditType,
      oauthFlowId: input.oauthFlowId
    };

    this.safeLog("info", "Audit event started", {
      ...correlation,
      auditStatus: "STARTED",
      ...auditFailureClassification(input),
      tags: ["oauth", "audit"]
    });

    try {
      if (generationFailed) {
        throw new AuditFailure("audit_generation_failed", "Audit id generation failed");
      }
      validateAuditInput(input);
      const persistenceMode = validatePersistenceMode(this.persistenceMode);
      const event = createAuditEvent(input, auditId, this.now());
      serializeAuditEvent(event);
      const shouldPersist =
        persistenceMode === "all" ||
        (persistenceMode === "errors_only" && input.auditStatus === "FAILURE");
      if (shouldPersist) {
        try {
          await this.persist(event);
        } catch (error) {
          if (error instanceof AuditFailure) throw error;
          throw new AuditFailure("audit_persistence_failed", "Audit persistence failed");
        }
      }

      this.safeLog("info", "Audit event completed", {
        ...event,
        persistenceMode,
        persistenceSkipped: !shouldPersist,
        durationMs: Date.now() - startedAt,
        tags: ["oauth", "audit"]
      });

      return {
        ...correlation,
        auditStatus: input.auditStatus,
        persisted: shouldPersist,
        persistenceSkipped: !shouldPersist
      };
    } catch (error) {
      const reasonCode = auditFailureReason(error);
      this.safeLog("error", "Audit event failed", {
        ...correlation,
        auditStatus: "FAILURE",
        reasonCode,
        expectedAuditEvent: input.auditType,
        durationMs: Date.now() - startedAt,
        tags: ["oauth", "audit", "error"]
      });

      return {
        ...correlation,
        auditStatus: input.auditStatus,
        persisted: false,
        failureReasonCode: reasonCode
      };
    }
  }

  private safeLog(
    level: "info" | "error",
    message: string,
    metadata: Record<string, unknown>
  ): void {
    try {
      this.logger[level](message, metadata);
    } catch {
      // Audit observability must never interfere with the OAuth transaction.
    }
  }
}

export const oauthAuditService = new OAuthAuditService();

export function newOAuthFlowId(): string {
  return randomUUID();
}

export function auditHash(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("base64url")}`;
}

export function auditCorrelation(result: AuditResult): Record<string, unknown> {
  return {
    oauthFlowId: result.oauthFlowId,
    auditId: result.auditId,
    auditType: result.auditType
  };
}

function validateAuditInput(input: AuditEventInput): void {
  if (!AUDIT_TYPES.includes(input.auditType) || !input.oauthFlowId) {
    throw new AuditFailure("audit_validation_failed", "Invalid audit event identity");
  }
  if (input.auditStatus !== "SUCCESS" && input.auditStatus !== "FAILURE") {
    throw new AuditFailure("audit_validation_failed", "Invalid audit event status");
  }
  if (input.reasonCode !== undefined) {
    if (
      input.auditStatus !== "FAILURE" ||
      typeof input.reasonCode !== "string" ||
      input.reasonCode.trim().length === 0
    ) {
      throw new AuditFailure("audit_validation_failed", "Invalid audit reason code");
    }
  }
  if (input.rootCauseCode !== undefined) {
    if (
      input.auditStatus !== "FAILURE" ||
      !input.reasonCode ||
      !isAuditRootCauseCode(input.rootCauseCode)
    ) {
      throw new AuditFailure("audit_validation_failed", "Invalid audit root cause code");
    }
  }
  for (const key of Object.keys(input.details ?? {})) {
    if (RESERVED_EVENT_FIELDS.has(key)) {
      throw new AuditFailure("audit_validation_failed", `Reserved audit field: ${key}`);
    }
  }
}

function validatePersistenceMode(value: string): AuditPersistenceMode {
  if (value === "all" || value === "errors_only" || value === "disabled") {
    return value;
  }
  throw new AuditFailure(
    "audit_validation_failed",
    "OAUTH_AUDIT_PERSISTENCE_MODE must be all, errors_only, or disabled"
  );
}

function createAuditEvent(
  input: AuditEventInput,
  auditId: string,
  timestamp: Date
): AuditEvent {
  const trace = getCurrentTraceContext();
  if (!trace) {
    throw new AuditFailure("audit_generation_failed", "Trace context is unavailable");
  }

  return {
    auditId,
    auditType: input.auditType,
    auditStatus: input.auditStatus,
    requestId: trace.requestId,
    traceId: trace.traceId,
    spanId: trace.spanId,
    oauthFlowId: input.oauthFlowId,
    eventTimestamp: timestamp.toISOString(),
    ...auditFailureClassification(input),
    ...(input.details ?? {})
  };
}

function auditFailureClassification(
  input: Pick<AuditEventInput, "reasonCode" | "rootCauseCode">
): Pick<AuditEvent, "reasonCode" | "rootCauseCode"> {
  return {
    ...(input.reasonCode ? { reasonCode: input.reasonCode } : {}),
    ...(input.rootCauseCode ? { rootCauseCode: input.rootCauseCode } : {})
  };
}

function serializeAuditEvent(event: AuditEvent): void {
  try {
    JSON.stringify(event);
  } catch {
    throw new AuditFailure("audit_serialization_failed", "Audit event is not serializable");
  }
}

async function persistAuditEvent(event: AuditEvent): Promise<void> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AUDIT_TIMEOUT_MS);

  try {
    const response = await fetch(supabaseRestUrl("oauth_audit_events"), {
      method: "POST",
      headers: {
        ...supabaseHeaders(),
        Prefer: "return=minimal"
      },
      body: JSON.stringify(auditEventPersistenceRow(event)),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new AuditFailure(
        "audit_persistence_failed",
        `Supabase audit insert failed with status ${response.status}`
      );
    }
  } catch (error) {
    if (error instanceof AuditFailure) throw error;
    if (controller.signal.aborted) {
      throw new AuditFailure("audit_timeout", "Audit persistence timed out");
    }
    throw new AuditFailure("audit_persistence_failed", "Audit persistence failed");
  } finally {
    clearTimeout(timeout);
  }
}

export function auditEventPersistenceRow(event: AuditEvent): AuditEventPersistenceRow {
  return {
    audit_id: event.auditId,
    audit_type: event.auditType,
    audit_status: event.auditStatus,
    request_id: event.requestId,
    trace_id: event.traceId,
    span_id: event.spanId,
    oauth_flow_id: event.oauthFlowId,
    event_timestamp: event.eventTimestamp,
    reason_code: event.reasonCode ?? null,
    root_cause_code: event.rootCauseCode ?? null,
    event_payload: event
  };
}

function auditFailureReason(error: unknown): AuditFailureReasonCode {
  return error instanceof AuditFailure ? error.reasonCode : "audit_unexpected_error";
}
