import { optional, parseAuthorizationDetails, stringClaim } from "../../../domain/oauth-values";
import type { JwtPayload, TokenClaims } from "../../../types";
import {
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult
} from "../../dto/oauth-response.dto";
import { normalizeRequestedScope } from "../scope-validation.service";
import { TokenIssuerService } from "../token-issuer.service";
import { ClientAuthenticationService } from "../client-authentication.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class TokenExchangeGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes: readonly string[];
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly tokenIssuer: TokenIssuerService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.grantTypes = [ports.config.tokenExchangeGrant];
    this.clientAuthentication = new ClientAuthenticationService(ports);
    this.tokenIssuer = new TokenIssuerService(ports);
  }

  async execute({ request, oauthFlowId }: TokenGrantContext) {
    const clientAuth = await this.clientAuthentication.authenticate(request, {
      allowPublic: false,
      required: true,
      oauthFlowId
    });
    if (!clientAuth.ok) return clientAuth.response;

    const subjectToken = request.parameters.subject_token;
    const subjectTokenType = request.parameters.subject_token_type;
    if (!subjectToken) return springParameterErrorResult("subject_token");
    if (!subjectTokenType) return springParameterErrorResult("subject_token_type");

    const stored = await this.ports.tokens.findAccessToken(subjectToken);
    const decoded = stored
      ? this.ports.jwt.decode<TokenClaims & JwtPayload>(stored.jwt)
      : this.ports.jwt.decode<TokenClaims & JwtPayload>(subjectToken);
    if (!stored && !decoded) {
      return oauthErrorResult("invalid_grant", "OAuth 2.0 Parameter: subject_token", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const subject = stored?.subject ?? stringClaim(decoded?.sub) ?? clientAuth.client.clientId;
    const claims = stored?.claims ?? decoded ?? {};
    const scope = normalizeRequestedScope(
      request.parameters.scope ?? stored?.scope ?? stringClaim(decoded?.scope),
      clientAuth.client,
      this.ports.config
    );
    if (!scope.ok) return scope.response;

    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client: clientAuth.client,
        oauthFlowId: stored?.oauthFlowId ?? oauthFlowId,
        grantType: this.ports.config.tokenExchangeGrant,
        subject,
        scope: scope.value,
        baseUrl: request.baseUrl,
        claims: { ...claims, audience: request.parameters.audience },
        authorizationDetails: parseAuthorizationDetails(
          optional(request.parameters, "authorization_details")
        )
      })
    );
  }
}
