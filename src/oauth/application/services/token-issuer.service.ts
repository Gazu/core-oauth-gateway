import { cleanCustomClaims, objectClaim, stringClaim } from "../../domain/oauth-values";
import type {
  JwtPayload,
  OAuthClient,
  StoredAccessToken,
  StoredRefreshToken,
  TokenClaims
} from "../../types";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

export type TokenSetInput = {
  client: OAuthClient;
  oauthFlowId: string;
  grantType: string;
  subject: string;
  scope: string;
  baseUrl: string;
  claims?: TokenClaims;
  nonce?: string;
  authorizationDetails?: unknown;
  includeRefreshToken?: boolean;
  includeIdToken?: boolean;
  previousRefreshTokenHash?: string;
};

export class TokenIssuerService {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async createTokenSet(input: TokenSetInput): Promise<Record<string, unknown>> {
    const now = this.ports.jwt.nowSeconds();
    const issuedAt = now * 1000;
    const accessTokenTtlSeconds =
      input.client.accessTokenTtlSeconds ?? this.ports.config.accessTokenTtlSeconds;
    const refreshTokenTtlSeconds =
      input.client.refreshTokenTtlSeconds ?? this.ports.config.refreshTokenTtlSeconds;
    const expiresAt = issuedAt + accessTokenTtlSeconds * 1000;
    const opaqueToken = this.ports.jwt.randomToken(32);
    const accessPayload: JwtPayload = {
      ...cleanCustomClaims(input.claims ?? {}),
      jti: this.ports.jwt.tokenHash(opaqueToken),
      sub: input.subject,
      iss: input.baseUrl,
      iat: now,
      exp: now + accessTokenTtlSeconds,
      azp: input.client.clientId,
      client_id: input.client.clientId,
      scope: input.scope,
      client_metadata: input.client.clientMetadata ?? {}
    };
    const accessJwt = await this.ports.jwt.sign(accessPayload);
    const accessToken = input.client.opaqueToken === false ? accessJwt : opaqueToken;
    const storedAccessToken: StoredAccessToken = {
      token: accessToken,
      tokenId: this.ports.jwt.tokenHash(accessToken),
      oauthFlowId: input.oauthFlowId,
      jwt: accessJwt,
      clientId: input.client.clientId,
      subject: input.subject,
      scope: input.scope,
      issuedAt,
      expiresAt,
      revoked: false,
      claims: accessPayload
    };

    const response: Record<string, unknown> = {
      access_token: accessToken,
      scope: input.scope,
      token_type: "Bearer",
      expires_in: accessTokenTtlSeconds
    };
    let refreshTokenHash: string | undefined;
    let storedRefreshToken: StoredRefreshToken | undefined;

    if (input.includeRefreshToken) {
      const refreshToken = this.ports.jwt.randomToken(32);
      refreshTokenHash = this.ports.audit.hash(refreshToken);
      storedRefreshToken = {
        token: refreshToken,
        tokenId: this.ports.jwt.tokenHash(refreshToken),
        oauthFlowId: input.oauthFlowId,
        clientId: input.client.clientId,
        subject: input.subject,
        scope: input.scope,
        issuedAt,
        expiresAt: issuedAt + refreshTokenTtlSeconds * 1000,
        revoked: false,
        userClaims: input.claims ?? {}
      };
      response.refresh_token = refreshToken;
    }

    if (input.includeIdToken) response.id_token = await this.createIdToken(input, now);
    if (input.authorizationDetails) {
      response.authorization_details = input.authorizationDetails;
    }

    await this.ports.tokens.saveTokens(storedAccessToken, storedRefreshToken);

    const tokensAudit = await this.ports.audit.record({
      auditType: "tokens_issued",
      auditStatus: "SUCCESS",
      oauthFlowId: input.oauthFlowId,
      details: {
        clientId: input.client.clientId,
        userId: input.subject,
        grantType: input.grantType,
        accessTokenHash: this.ports.audit.hash(accessToken),
        refreshTokenHash
      }
    });

    if (input.previousRefreshTokenHash && refreshTokenHash) {
      const refreshAudit = await this.ports.audit.record({
        auditType: "refresh_token_used",
        auditStatus: "SUCCESS",
        oauthFlowId: input.oauthFlowId,
        details: {
          clientId: input.client.clientId,
          userId: input.subject,
          oldRefreshTokenHash: input.previousRefreshTokenHash,
          newRefreshTokenHash: refreshTokenHash
        }
      });
      this.ports.loggers.token.info("Refresh token used", {
        oldRefreshTokenHash: input.previousRefreshTokenHash,
        newRefreshTokenHash: refreshTokenHash,
        clientId: input.client.clientId,
        ...this.ports.audit.correlation(refreshAudit),
        tags: ["oauth", "refresh-token"]
      });
    }

    this.ports.loggers.token.info("Token set issued", {
      accessTokenHash: this.ports.audit.hash(accessToken),
      clientId: input.client.clientId,
      subject: input.subject,
      scope: input.scope,
      expiresAt,
      refreshTokenIssued: Boolean(response.refresh_token),
      idTokenIssued: Boolean(response.id_token),
      grantType: input.grantType,
      ...this.ports.audit.correlation(tokensAudit),
      tags: ["oauth", "token"]
    });

    return response;
  }

  private createIdToken(input: TokenSetInput, now: number): Promise<string> {
    const idt = objectClaim(input.claims?.idt);
    const subject = stringClaim(idt?.sub) ?? input.subject;
    return this.ports.jwt.sign({
      ...idt,
      jti: this.ports.jwt.jwtId(),
      sub: subject,
      iss: input.baseUrl,
      aud: input.client.clientId,
      iat: now,
      exp:
        now +
        (input.client.accessTokenTtlSeconds ?? this.ports.config.accessTokenTtlSeconds),
      nonce: input.nonce
    });
  }
}
