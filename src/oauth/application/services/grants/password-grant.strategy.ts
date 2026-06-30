import { stringClaim, splitScope } from "../../../domain/oauth-values";
import type { TokenClaims } from "../../../types";
import {
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult
} from "../../dto/oauth-response.dto";
import { normalizeRequestedScope } from "../scope-validation.service";
import { AuditEventService } from "../audit-event.service";
import { TokenIssuerService } from "../token-issuer.service";
import { ClientAuthenticationService } from "../client-authentication.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class PasswordGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes = ["password"];
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly tokenIssuer: TokenIssuerService;
  private readonly auditEvents: AuditEventService;
  private readonly passwordUsers: Record<string, { password: string; claims: TokenClaims }>;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.clientAuthentication = new ClientAuthenticationService(ports);
    this.tokenIssuer = new TokenIssuerService(ports);
    this.auditEvents = new AuditEventService(ports);
    this.passwordUsers = loadPasswordUsers(ports.config.passwordGrantEnabled, ports.config.passwordGrantUsersJson, ports);
  }

  async execute({ request, oauthFlowId }: TokenGrantContext) {
    if (!this.ports.config.passwordGrantEnabled) {
      return oauthErrorResult("unsupported_grant_type", "Password grant is disabled", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const username = request.parameters.username;
    const password = request.parameters.password;
    if (!username) return springParameterErrorResult("username");
    if (!password) return springParameterErrorResult("password");

    const clientAuth = await this.clientAuthentication.authenticate(request, {
      allowPublic: false,
      required: true,
      oauthFlowId
    });
    if (!clientAuth.ok) return clientAuth.response;

    const user = this.passwordUsers[username];
    if (!user || user.password !== password) {
      await this.auditEvents.recordAuthenticationFailure(
        oauthFlowId,
        clientAuth.client.clientId,
        "invalid_credentials"
      );
      return oauthErrorResult("invalid_grant", "Bad credentials", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const scope = normalizeRequestedScope(
      request.parameters.scope,
      clientAuth.client,
      this.ports.config
    );
    if (!scope.ok) return scope.response;
    const subject = stringClaim(user.claims.sub) ?? username;
    const audit = await this.ports.audit.record({
      auditType: "user_authenticated",
      auditStatus: "SUCCESS",
      oauthFlowId,
      details: { userId: subject, clientId: clientAuth.client.clientId }
    });
    this.ports.loggers.token.info("User authenticated", {
      userId: subject,
      clientId: clientAuth.client.clientId,
      ...this.ports.audit.correlation(audit),
      tags: ["oauth", "authentication"]
    });

    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client: clientAuth.client,
        oauthFlowId,
        grantType: "password",
        subject,
        scope: scope.value,
        baseUrl: request.baseUrl,
        claims: user.claims,
        includeRefreshToken: true,
        includeIdToken: splitScope(scope.value).includes("openid")
      })
    );
  }
}

function loadPasswordUsers(
  enabled: boolean,
  usersJson: string | undefined,
  ports: OAuthApplicationPorts
): Record<string, { password: string; claims: TokenClaims }> {
  if (!enabled || !usersJson) return {};

  try {
    const parsed = JSON.parse(usersJson) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const users: Record<string, { password: string; claims: TokenClaims }> = {};
    for (const [username, value] of Object.entries(parsed)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      const candidate = value as { password?: unknown; claims?: unknown };
      if (typeof candidate.password !== "string") continue;
      if (!candidate.claims || typeof candidate.claims !== "object" || Array.isArray(candidate.claims)) continue;
      users[username] = {
        password: candidate.password,
        claims: candidate.claims as TokenClaims
      };
    }
    return users;
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Password grant users configuration is invalid";
    ports.loggers.token.error(message, {
      tags: ["oauth", "configuration"],
      exception: error
    });
    return {};
  }
}
