import { splitScope, stringClaim } from "../../../domain/oauth-values";
import {
  invalidClientResult,
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult
} from "../../dto/oauth-response.dto";
import { TokenIssuerService } from "../token-issuer.service";
import { ClientAuthenticationService } from "../client-authentication.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class AuthorizationCodeGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes = ["authorization_code"];
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly tokenIssuer: TokenIssuerService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.clientAuthentication = new ClientAuthenticationService(ports);
    this.tokenIssuer = new TokenIssuerService(ports);
  }

  async execute({ request, oauthFlowId }: TokenGrantContext) {
    const code = request.parameters.code;
    if (!code) return springParameterErrorResult("code");

    const authorizationCode = this.ports.state.getAuthorizationCode(code);
    if (
      !authorizationCode ||
      authorizationCode.consumed ||
      authorizationCode.expiresAt <= Date.now()
    ) {
      return oauthErrorResult("invalid_grant", "OAuth 2.0 Parameter: code", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const client = this.ports.state.getClient(authorizationCode.clientId);
    if (!client) return invalidClientResult();

    const clientAuth = await this.clientAuthentication.authenticate(request, {
      allowPublic: true,
      required: client.type === "confidential",
      expectedClientId: client.clientId,
      oauthFlowId: authorizationCode.oauthFlowId ?? oauthFlowId
    });
    if (!clientAuth.ok) return clientAuth.response;

    const redirectUri = request.parameters.redirect_uri;
    if (redirectUri && redirectUri !== authorizationCode.redirectUri) {
      return oauthErrorResult("invalid_grant", "OAuth 2.0 Parameter: redirect_uri", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    if (authorizationCode.codeChallenge) {
      const verifier = request.parameters.code_verifier;
      if (!verifier) return springParameterErrorResult("code_verifier");
      if (
        authorizationCode.codeChallengeMethod !== "S256" ||
        this.ports.jwt.s256(verifier) !== authorizationCode.codeChallenge
      ) {
        return oauthErrorResult("invalid_grant", "OAuth 2.0 Parameter: code_verifier", {
          errorUri: this.ports.config.pkceErrorUri
        });
      }
    }

    authorizationCode.consumed = true;
    await this.ports.state.saveAuthorizationCode(authorizationCode);
    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client,
        oauthFlowId: authorizationCode.oauthFlowId ?? oauthFlowId,
        grantType: "authorization_code",
        subject: stringClaim(authorizationCode.userClaims.sub) ?? "subject",
        scope: authorizationCode.scope,
        baseUrl: request.baseUrl,
        claims: authorizationCode.userClaims,
        nonce: authorizationCode.nonce,
        authorizationDetails: authorizationCode.authorizationDetails,
        includeRefreshToken: true,
        includeIdToken: splitScope(authorizationCode.scope).includes("openid")
      })
    );
  }
}
