import {
  introspectionCustomClaims,
  objectClaim,
  required
} from "../../domain/oauth-values";
import {
  jsonResult,
  oauthErrorResult,
  springParameterErrorResult,
  type OAuthResponseDto
} from "../dto/oauth-response.dto";
import type { OAuthParameters } from "../dto/oauth-request.dto";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

export class GetTokenInfoUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const token = required(parameters, "token");
    if (!token) return springParameterErrorResult("token");

    const stored = await this.ports.tokens.findAccessToken(token);
    if (stored && !stored.revoked && stored.expiresAt > Date.now()) {
      this.ports.loggers.token.info("Opaque token exchanged for signed JWT", {
        tokenHash: this.ports.jwt.tokenHash(token),
        clientId: stored.clientId,
        subject: stored.subject,
        scope: stored.scope,
        expiresAt: stored.expiresAt,
        oauthFlowId: stored.oauthFlowId,
        tags: ["oauth", "tokeninfo"]
      });
      return jsonResult({ access_token: stored.jwt });
    }

    if (this.ports.jwt.decode(token)) {
      this.ports.loggers.token.info("JWT tokeninfo passthrough", {
        tokenHash: this.ports.jwt.tokenHash(token),
        tags: ["oauth", "tokeninfo"]
      });
      return jsonResult({ access_token: token });
    }

    return oauthErrorResult("invalid_token", "The access token is invalid", {
      errorUri: "https://datatracker.ietf.org/doc/html/rfc6750#section-3.1"
    });
  }
}

export class IntrospectTokenUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const token = required(parameters, "token");
    if (!token) return springParameterErrorResult("token");

    const stored = await this.ports.tokens.findAccessToken(token);
    if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
      this.ports.loggers.token.info("Token introspection inactive", {
        tokenHash: this.ports.jwt.tokenHash(token),
        oauthFlowId: stored?.oauthFlowId,
        tags: ["oauth", "introspection"]
      });
      return jsonResult({ active: false });
    }

    this.ports.loggers.token.info("Token introspection active", {
      tokenHash: this.ports.jwt.tokenHash(token),
      clientId: stored.clientId,
      subject: stored.subject,
      scope: stored.scope,
      oauthFlowId: stored.oauthFlowId,
      tags: ["oauth", "introspection"]
    });

    return jsonResult({
      ...introspectionCustomClaims(stored.claims),
      active: true,
      sub: stored.subject,
      client_id: stored.clientId,
      scope: stored.scope,
      token_type: "Bearer",
      exp: Math.floor(stored.expiresAt / 1000),
      iat: Math.floor(stored.issuedAt / 1000),
      jti: stored.tokenId
    });
  }
}

export class GetUserInfoUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const token = parameters.access_token ?? parameters.token;
    if (!token) {
      return oauthErrorResult("invalid_request", "OAuth 2.0 Parameter: access_token", {
        status: 401,
        errorUri: "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError",
        headers: {
          "WWW-Authenticate":
            'Bearer error="invalid_request", error_description="OAuth 2.0 Parameter: access_token"'
        }
      });
    }

    const stored = await this.ports.tokens.findAccessToken(token);
    if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
      return oauthErrorResult("invalid_token", "The access token is invalid", {
        status: 401,
        errorUri: "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError",
        headers: {
          "WWW-Authenticate":
            'Bearer error="invalid_token", error_description="The access token is invalid"'
        }
      });
    }

    this.ports.loggers.token.info("UserInfo returned claims", {
      tokenHash: this.ports.jwt.tokenHash(token),
      clientId: stored.clientId,
      subject: stored.subject,
      scope: stored.scope,
      oauthFlowId: stored.oauthFlowId,
      tags: ["oauth", "userinfo"]
    });

    return jsonResult({
      sub: stored.subject,
      profile: objectClaim(stored.claims.profile) ?? {},
      scope: stored.scope,
      client_id: stored.clientId
    });
  }
}
