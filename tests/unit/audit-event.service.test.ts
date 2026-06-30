import { describe, expect, it } from "vitest";
import { AuditEventService } from "../../src/oauth/application/services/audit-event.service";
import { createTestOAuthPorts } from "./helpers/oauth-ports";

describe("AuditEventService", () => {
  it("propagates client authentication root causes to audit and OAuth logs", async () => {
    const ports = createTestOAuthPorts();
    const service = new AuditEventService(ports);

    await service.recordClientAuthenticationFailure(
      "oauth-flow-id",
      "invalid_client_assertion",
      "client-id",
      "private_key_jwt",
      "assertion_expired"
    );

    expect(ports.audit.record).toHaveBeenCalledWith({
      auditType: "client_authentication_failed",
      auditStatus: "FAILURE",
      oauthFlowId: "oauth-flow-id",
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "assertion_expired",
      details: {
        clientId: "client-id",
        authenticationMethod: "private_key_jwt"
      }
    });
    expect(ports.loggers.clientAuth.error).toHaveBeenCalledWith(
      "Client authentication failed",
      expect.objectContaining({
        reasonCode: "invalid_client_assertion",
        rootCauseCode: "assertion_expired",
        clientId: "client-id",
        method: "private_key_jwt",
        auditId: "audit-id"
      })
    );
  });
});
