import type { AuditRootCauseCode } from "../../domain/value-objects/audit-root-cause";

export type AuditStatus = "SUCCESS" | "FAILURE";

export type AuditEventInput = {
  auditType: string;
  auditStatus: AuditStatus;
  oauthFlowId: string;
  reasonCode?: string;
  rootCauseCode?: AuditRootCauseCode;
  details?: Record<string, unknown>;
};

export type AuditResult = {
  auditId: string;
  auditType: string;
  auditStatus: AuditStatus;
  oauthFlowId: string;
  persisted: boolean;
  persistenceSkipped?: boolean;
  failureReasonCode?: string;
};

export interface AuditServicePort {
  record(input: AuditEventInput): Promise<AuditResult>;
  newFlowId(): string;
  hash(value: string): string;
  correlation(result: AuditResult): Record<string, unknown>;
}
