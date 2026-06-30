import type { OAuthRequestDto } from "../dto/oauth-request.dto";
import {
  oauthErrorResult,
  springParameterErrorResult,
  type OAuthResponseDto
} from "../dto/oauth-response.dto";
import { AuthorizationCodeGrantStrategy } from "../services/grants/authorization-code-grant.strategy";
import { ClientCredentialsGrantStrategy } from "../services/grants/client-credentials-grant.strategy";
import { JwtBearerGrantStrategy } from "../services/grants/jwt-bearer-grant.strategy";
import { PasswordGrantStrategy } from "../services/grants/password-grant.strategy";
import { RefreshTokenGrantStrategy } from "../services/grants/refresh-token-grant.strategy";
import { TokenExchangeGrantStrategy } from "../services/grants/token-exchange-grant.strategy";
import type { TokenGrantStrategy } from "../services/grants/token-grant.strategy";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

export class IssueTokenUseCase {
  private readonly strategies: Map<string, TokenGrantStrategy>;

  constructor(
    private readonly ports: OAuthApplicationPorts,
    strategies?: TokenGrantStrategy[]
  ) {
    const configuredStrategies = strategies ?? [
      new ClientCredentialsGrantStrategy(ports),
      new PasswordGrantStrategy(ports),
      new AuthorizationCodeGrantStrategy(ports),
      new JwtBearerGrantStrategy(ports),
      new RefreshTokenGrantStrategy(ports),
      new TokenExchangeGrantStrategy(ports)
    ];
    this.strategies = new Map(
      configuredStrategies.flatMap((strategy) =>
        strategy.grantTypes.map((grantType) => [grantType, strategy] as const)
      )
    );
  }

  async execute(request: OAuthRequestDto): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const grantType = request.parameters.grant_type;
    if (!grantType) return springParameterErrorResult("grant_type");

    const strategy = this.strategies.get(grantType);
    if (!strategy) {
      return oauthErrorResult("unsupported_grant_type", "OAuth 2.0 Parameter: grant_type", {
        errorUri: this.ports.config.tokenErrorUri
      });
    }

    return strategy.execute({ request, oauthFlowId: this.ports.audit.newFlowId() });
  }
}
