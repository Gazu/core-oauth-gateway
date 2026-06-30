import { splitScope } from "../../../domain/oauth-values";
import {
  invalidClientResult,
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult
} from "../../dto/oauth-response.dto";
import { normalizeRequestedScope } from "../scope-validation.service";
import { TokenIssuerService } from "../token-issuer.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class RefreshTokenGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes = ["refresh_token"];
  private readonly tokenIssuer: TokenIssuerService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.tokenIssuer = new TokenIssuerService(ports);
  }

  async execute({ request, oauthFlowId }: TokenGrantContext) {
    const refreshToken = request.parameters.refresh_token;
    if (!refreshToken) return springParameterErrorResult("refresh_token");

    const stored = await this.ports.tokens.findRefreshToken(refreshToken);
    if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
      return oauthErrorResult("invalid_grant", "OAuth 2.0 Parameter: refresh_token", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const client = this.ports.state.getClient(stored.clientId);
    if (!client) return invalidClientResult();
    if (!client.grantTypes.includes("refresh_token")) {
      return oauthErrorResult("unauthorized_client", "OAuth 2.0 Parameter: grant_type", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const scope = normalizeRequestedScope(
      request.parameters.scope ?? stored.scope,
      client,
      this.ports.config
    );
    if (!scope.ok) return scope.response;

    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client,
        oauthFlowId: stored.oauthFlowId ?? oauthFlowId,
        grantType: "refresh_token",
        subject: stored.subject,
        scope: scope.value,
        baseUrl: request.baseUrl,
        claims: stored.userClaims,
        includeRefreshToken: true,
        includeIdToken: splitScope(scope.value).includes("openid"),
        previousRefreshTokenHash: this.ports.audit.hash(refreshToken)
      })
    );
  }
}
