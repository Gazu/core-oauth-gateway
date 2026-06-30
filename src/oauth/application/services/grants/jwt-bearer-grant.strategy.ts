import { stringClaim } from "../../../domain/oauth-values";
import type { JwtPayload, TokenClaims } from "../../../types";
import { AuditEventService } from "../audit-event.service";
import {
  invalidJwtBearerAssertionResult,
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult
} from "../../dto/oauth-response.dto";
import { normalizeRequestedScope } from "../scope-validation.service";
import { TokenIssuerService } from "../token-issuer.service";
import { ClientAssertionValidationService } from "../client-assertion-validation.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class JwtBearerGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes: readonly string[];
  private readonly assertionValidation: ClientAssertionValidationService;
  private readonly tokenIssuer: TokenIssuerService;
  private readonly auditEvents: AuditEventService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.grantTypes = [ports.config.jwtBearerGrant, ports.config.jwtBearerGrantCompat];
    this.assertionValidation = new ClientAssertionValidationService(ports);
    this.tokenIssuer = new TokenIssuerService(ports);
    this.auditEvents = new AuditEventService(ports);
  }

  async execute({ request, oauthFlowId }: TokenGrantContext) {
    const assertion = request.parameters.assertion;
    if (!assertion) return springParameterErrorResult("assertion");

    const validation = await this.assertionValidation.validate<TokenClaims & JwtPayload>({
      assertion,
      acceptedAudiences: [
        request.baseUrl,
        `${request.baseUrl}/oauth2/v1/token`
      ],
      consumeReplay: false
    });
    if (!validation.valid) {
      await this.auditEvents.recordClientAuthenticationFailure(
        oauthFlowId,
        validation.reasonCode,
        validation.clientId,
        "private_key_jwt",
        validation.rootCauseCode
      );
      return invalidJwtBearerAssertionResult(this.ports.config.tokenErrorUri);
    }

    const { client, payload } = validation;
    if (
      !client.grantTypes.includes(this.ports.config.jwtBearerGrant) &&
      !client.grantTypes.includes(this.ports.config.jwtBearerGrantCompat)
    ) {
      return oauthErrorResult("unauthorized_client", "OAuth 2.0 Parameter: grant_type", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const replayFailure = await this.assertionValidation.rememberReplay(client, payload);
    if (replayFailure) {
      await this.auditEvents.recordClientAuthenticationFailure(
        oauthFlowId,
        replayFailure.reasonCode,
        replayFailure.clientId,
        "private_key_jwt",
        replayFailure.rootCauseCode
      );
      return invalidJwtBearerAssertionResult(this.ports.config.tokenErrorUri);
    }

    const clientAudit = await this.ports.audit.record({
      auditType: "client_authenticated",
      auditStatus: "SUCCESS",
      oauthFlowId,
      details: { clientId: client.clientId, authenticationMethod: "private_key_jwt" }
    });
    this.ports.loggers.clientAuth.info("Client authenticated", {
      clientId: client.clientId,
      method: "private_key_jwt",
      ...this.ports.audit.correlation(clientAudit),
      tags: ["oauth", "client-auth", "jwt-bearer"]
    });

    const scope = normalizeRequestedScope(
      request.parameters.scope ?? stringClaim(payload.scope),
      client,
      this.ports.config
    );
    if (!scope.ok) return scope.response;
    const subject =
      stringClaim(payload.userId) ??
      stringClaim(payload.user_id) ??
      stringClaim(payload.sub) ??
      client.clientId;

    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client,
        oauthFlowId,
        grantType: this.ports.config.jwtBearerGrant,
        subject,
        scope: scope.value,
        baseUrl: request.baseUrl,
        claims: payload,
        includeRefreshToken: client.grantTypes.includes("refresh_token")
      })
    );
  }
}
