import type { AuditResult } from "../ports/audit-service.port";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";
import type { OAuthParameters } from "../dto/oauth-request.dto";
import { optional } from "../../domain/oauth-values";
import type { AuditRootCauseCode } from "../../domain/value-objects/audit-root-cause";

export type ClientAuthMethod = "client_secret_basic" | "private_key_jwt" | "none";

export class AuditEventService {
  constructor(private readonly ports: Pick<OAuthApplicationPorts, "audit" | "loggers">) {}

  async recordClientAuthenticationFailure(
    oauthFlowId: string,
    reasonCode: string,
    clientId?: string,
    method?: ClientAuthMethod,
    rootCauseCode?: AuditRootCauseCode
  ): Promise<AuditResult> {
    const audit = await this.ports.audit.record({
      auditType: "client_authentication_failed",
      auditStatus: "FAILURE",
      oauthFlowId,
      reasonCode,
      rootCauseCode,
      details: { clientId, authenticationMethod: method }
    });
    this.ports.loggers.clientAuth.error("Client authentication failed", {
      reasonCode,
      rootCauseCode,
      clientId,
      method,
      ...this.ports.audit.correlation(audit),
      tags: ["oauth", "client-auth"]
    });
    return audit;
  }

  async recordAuthenticationFailure(
    oauthFlowId: string,
    clientId: string,
    reasonCode: string
  ): Promise<AuditResult> {
    const audit = await this.ports.audit.record({
      auditType: "authentication_failed",
      auditStatus: "FAILURE",
      oauthFlowId,
      reasonCode,
      details: { clientId }
    });
    this.ports.loggers.token.error("User authentication failed", {
      clientId,
      reasonCode,
      ...this.ports.audit.correlation(audit),
      tags: ["oauth", "authentication"]
    });
    return audit;
  }

  async recordAuthorizationFailure(
    oauthFlowId: string,
    parameters: OAuthParameters,
    reasonCode: string,
    parameter?: string
  ): Promise<AuditResult> {
    const clientId = optional(parameters, "client_id");
    const audit = await this.ports.audit.record({
      auditType: "authorization_failed",
      auditStatus: "FAILURE",
      oauthFlowId,
      reasonCode,
      details: { clientId, parameter }
    });
    this.ports.loggers.token.error("OAuth authorization request rejected", {
      clientId,
      reasonCode,
      parameter,
      ...this.ports.audit.correlation(audit),
      tags: ["oauth", "authorization"]
    });
    return audit;
  }
}
