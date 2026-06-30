import type {
  AuditEventInput,
  AuditResult,
  AuditServicePort
} from "@/oauth/application/ports/audit-service.port";
import {
  auditCorrelation,
  auditHash,
  newOAuthFlowId,
  oauthAuditService
} from "@/oauth/audit";

export class OAuthAuditAdapter implements AuditServicePort {
  async record(input: AuditEventInput): Promise<AuditResult> {
    return oauthAuditService.record(input as Parameters<typeof oauthAuditService.record>[0]);
  }

  newFlowId(): string {
    return newOAuthFlowId();
  }

  hash(value: string): string {
    return auditHash(value);
  }

  correlation(result: AuditResult): Record<string, unknown> {
    return auditCorrelation(result as Parameters<typeof auditCorrelation>[0]);
  }
}
