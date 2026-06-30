import { normalizeRequestedScope } from "../scope-validation.service";
import { jsonResult, oauthErrorResult } from "../../dto/oauth-response.dto";
import { ClientAuthenticationService } from "../client-authentication.service";
import { TokenIssuerService } from "../token-issuer.service";
import type { OAuthApplicationPorts } from "../../ports/oauth-application.ports";
import type { TokenGrantContext, TokenGrantStrategy } from "./token-grant.strategy";

export class ClientCredentialsGrantStrategy implements TokenGrantStrategy {
  readonly grantTypes = ["client_credentials"];
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly tokenIssuer: TokenIssuerService;

  constructor(private readonly ports: OAuthApplicationPorts) {
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

    const client = clientAuth.client;
    if (!client.grantTypes.includes("client_credentials")) {
      return oauthErrorResult("unauthorized_client", "OAuth 2.0 Parameter: grant_type", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    const scope = normalizeRequestedScope(request.parameters.scope, client, this.ports.config);
    if (!scope.ok) return scope.response;

    return jsonResult(
      await this.tokenIssuer.createTokenSet({
        client,
        oauthFlowId,
        grantType: "client_credentials",
        subject: client.clientId,
        scope: scope.value,
        baseUrl: request.baseUrl
      })
    );
  }
}
