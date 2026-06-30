import {
  addTokenDescriptor,
  claimsMatch,
  optional,
  parseRequiredClaims,
  required,
  stringClaim
} from "../../domain/oauth-values";
import type { OAuthParameters } from "../dto/oauth-request.dto";
import {
  emptyResult,
  jsonResult,
  springParameterErrorResult,
  type OAuthResponseDto
} from "../dto/oauth-response.dto";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

export class RevokeTokenUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const token = required(parameters, "token");
    if (!token) return springParameterErrorResult("token");

    const stored =
      (await this.ports.tokens.findAccessToken(token)) ??
      (await this.ports.tokens.findRefreshToken(token));
    const revoked = await this.ports.tokens.revokeToken(token);
    const oauthFlowId = stored?.oauthFlowId ?? this.ports.audit.newFlowId();
    const audit = revoked
      ? await this.ports.audit.record({
          auditType: "token_revoked",
          auditStatus: "SUCCESS",
          oauthFlowId,
          details: {
            clientId: stored?.clientId,
            userId: stored?.subject,
            tokenHash: this.ports.audit.hash(token)
          }
        })
      : undefined;
    this.ports.loggers.token.info("Token revocation requested", {
      tokenHash: this.ports.audit.hash(token),
      revoked,
      oauthFlowId,
      ...(audit ? this.ports.audit.correlation(audit) : {}),
      tags: ["oauth", "revocation"]
    });

    return emptyResult();
  }
}

export class ListAccessTokensUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const assertion = required(parameters, "assertion");
    if (!assertion) return springParameterErrorResult("assertion");

    const assertionPayload = this.ports.jwt.decode(assertion);
    if (!assertionPayload || this.ports.jwt.isExpired(assertionPayload)) {
      return springParameterErrorResult("assertion");
    }

    const clientFilter = optional(parameters, "client_id")
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const requiredClaims = parseRequiredClaims(optional(parameters, "required_claims"));
    const { accessTokens, refreshTokens } = await this.ports.tokens.listTokens();
    const response: Record<string, unknown[]> = {};

    for (const token of accessTokens) {
      if (token.revoked || token.expiresAt <= Date.now()) continue;
      if (clientFilter?.length && !clientFilter.includes(token.clientId)) continue;
      if (!claimsMatch(token.claims, requiredClaims)) continue;
      addTokenDescriptor(response, token.clientId, {
        token_type: "access_token",
        sub: token.subject,
        exp: token.expiresAt,
        iat: token.issuedAt,
        scope: token.scope,
        token_id: token.tokenId
      });
    }

    for (const token of refreshTokens) {
      if (token.revoked || token.expiresAt <= Date.now()) continue;
      if (clientFilter?.length && !clientFilter.includes(token.clientId)) continue;
      addTokenDescriptor(response, token.clientId, {
        token_type: "refresh_token",
        sub: token.subject,
        exp: token.expiresAt,
        iat: token.issuedAt,
        scope: token.scope,
        token_id: token.tokenId
      });
    }

    return jsonResult(response);
  }
}

export class RevokeTokenByIdUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    if (!required(parameters, "assertion")) return springParameterErrorResult("assertion");
    const tokenId = required(parameters, "token_id");
    if (!tokenId) return springParameterErrorResult("token_id");

    await this.ports.tokens.revokeTokenById(tokenId);
    return emptyResult();
  }
}

export class RevokeTokensBySubjectUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const assertion = required(parameters, "assertion");
    if (!assertion) return springParameterErrorResult("assertion");

    const assertionPayload = this.ports.jwt.decode(assertion);
    if (!assertionPayload || this.ports.jwt.isExpired(assertionPayload)) {
      return springParameterErrorResult("assertion");
    }

    const subject = optional(parameters, "sub") ?? stringClaim(assertionPayload.sub);
    const clientFilter = optional(parameters, "client_id")
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const deletedTokenCount = await this.ports.tokens.revokeTokensBySubject(
      subject,
      clientFilter
    );

    return jsonResult({ deletedTokenCount });
  }
}
