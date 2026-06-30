import type { OAuthRequestDto } from "../../dto/oauth-request.dto";
import type { OAuthResponseDto } from "../../dto/oauth-response.dto";

export type TokenGrantContext = {
  request: OAuthRequestDto;
  oauthFlowId: string;
};

export interface TokenGrantStrategy {
  readonly grantTypes: readonly string[];
  execute(context: TokenGrantContext): Promise<OAuthResponseDto>;
}
