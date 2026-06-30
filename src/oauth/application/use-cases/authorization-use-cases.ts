import {
  constrainUserScope,
  optional,
  parseAuthorizationDetails,
  required,
  splitScope,
  stringClaim
} from "../../domain/oauth-values";
import type {
  AuthorizationCode,
  AuthorizationRequest,
  JwtPayload,
  OAuthClient,
  TokenClaims
} from "../../types";
import { AuditEventService } from "../services/audit-event.service";
import type {
  OAuthParameters,
  OAuthRequestDto
} from "../dto/oauth-request.dto";
import {
  jsonResult,
  oauthErrorResult,
  redirectErrorResult,
  springParameterErrorResult,
  type OAuthResponseDto
} from "../dto/oauth-response.dto";
import { ClientAuthenticationService } from "../services/client-authentication.service";
import { normalizeRequestedScope } from "../services/scope-validation.service";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";

type AuthDetailsBody = { oauth_key?: string; auth_jwt?: string };
type UserAuthorizeBody = { oauth_key?: string; user_jwt?: string };
type UserErrorBody = { oauth_key?: string; error_jwt?: string };

export class AuthorizeUseCase {
  private readonly auditEvents: AuditEventService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.auditEvents = new AuditEventService(ports);
  }

  async execute(request: OAuthRequestDto): Promise<OAuthResponseDto> {
    const oauthFlowId = this.ports.audit.newFlowId();
    await this.ports.maintenance.cleanup();
    const parameters = paramsWithRequestUri(request.parameters, this.ports);
    const validation = validateAuthorizationParams(parameters, true, this.ports);

    if (!validation.ok) {
      await this.auditEvents.recordAuthorizationFailure(
        oauthFlowId,
        parameters,
        validation.reasonCode,
        validation.parameter
      );
      return validation.response;
    }

    const providerId = validation.client.oauthAuthenticationProvider;
    const provider = providerId
      ? this.ports.state.getAuthenticationProvider(providerId)
      : undefined;
    if (!provider) {
      await this.auditEvents.recordAuthorizationFailure(
        oauthFlowId,
        parameters,
        "authentication_provider_not_configured",
        "oauth_authentication_provider"
      );
      return oauthErrorResult(
        "invalid_request",
        "OAuth authentication provider is not configured",
        { errorUri: this.ports.config.authorizationErrorUri }
      );
    }

    const oauthKey = this.ports.jwt.randomToken(11);
    const authRequest: AuthorizationRequest = {
      oauthKey,
      oauthFlowId,
      clientId: validation.client.clientId,
      redirectUri: validation.redirectUri,
      scope: validation.scope,
      state: optional(parameters, "state"),
      codeChallenge: optional(parameters, "code_challenge"),
      codeChallengeMethod: optional(parameters, "code_challenge_method"),
      nonce: optional(parameters, "nonce"),
      responseMode: optional(parameters, "response_mode"),
      authorizationDetails: parseAuthorizationDetails(optional(parameters, "authorization_details")),
      consentRequired: validation.client.requireConsent ?? false,
      clientMetadata: validation.client.clientMetadata,
      params: parameters,
      expiresAt: Date.now() + this.ports.config.authorizationCodeTtlSeconds * 1000
    };

    await this.ports.state.saveAuthorizationRequest(authRequest);

    const issuedAt = this.ports.jwt.nowSeconds();
    const oauthKeySignature = await this.ports.jwt.sign({
      jti: this.ports.jwt.jwtId(),
      iat: issuedAt,
      exp: issuedAt + this.ports.config.authorizationCodeTtlSeconds,
      iss: request.baseUrl,
      aud: provider.providerId,
      oauth_key: oauthKey,
      oauth_flow_id: oauthFlowId,
      client_id: validation.client.clientId,
      consent_required: authRequest.consentRequired,
      scope: validation.scope,
      redirect_uri: validation.redirectUri,
      state: authRequest.state,
      client_metadata: validation.client.clientMetadata,
      ui_locales: optional(parameters, "ui_locales"),
      acr_values: optional(parameters, "acr_values")
    });

    const loginUrl = new URL(provider.loginUrl);
    loginUrl.searchParams.set("oauth_key", oauthKey);
    loginUrl.searchParams.set("oauth_key_signature", oauthKeySignature);

    const authorizationAudit = await this.ports.audit.record({
      auditType: "authorization_requested",
      auditStatus: "SUCCESS",
      oauthFlowId,
      details: {
        clientId: validation.client.clientId,
        responseType: "code",
        scope: validation.scope,
        authenticationProviderId: provider.providerId
      }
    });
    this.ports.loggers.token.info("OAuth authorization flow started", {
      oauthFlowId,
      clientId: validation.client.clientId,
      authenticationProviderId: provider.providerId,
      ...this.ports.audit.correlation(authorizationAudit),
      tags: ["oauth", "authorization"]
    });

    return jsonResult({}, { status: 302, headers: { Location: loginUrl.toString() } });
  }
}

export class PushedAuthorizeUseCase {
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly auditEvents: AuditEventService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.clientAuthentication = new ClientAuthenticationService(ports);
    this.auditEvents = new AuditEventService(ports);
  }

  async execute(request: OAuthRequestDto): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const oauthFlowId = this.ports.audit.newFlowId();
    const clientAuth = await this.clientAuthentication.authenticate(request, {
      allowPublic: true,
      required: false,
      oauthFlowId
    });
    const hintedClientId = request.parameters.client_id;
    const hintedClient = hintedClientId
      ? this.ports.state.getClient(hintedClientId)
      : undefined;

    if (!clientAuth.ok && !hintedClientId) return clientAuth.response;
    if (hintedClient?.type === "confidential" && !clientAuth.ok) return clientAuth.response;
    const validation = validateAuthorizationParams(
      request.parameters,
      false,
      this.ports,
      clientAuth.ok ? clientAuth.client : undefined
    );
    if (!validation.ok) {
      await this.auditEvents.recordAuthorizationFailure(
        oauthFlowId,
        request.parameters,
        validation.reasonCode,
        validation.parameter
      );
      return validation.response;
    }

    const requestUri = `urn:ietf:params:request_uri:${this.ports.jwt.randomToken(32)}`;
    await this.ports.state.savePushedRequest({
      requestUri,
      params: request.parameters,
      expiresAt: Date.now() + this.ports.config.requestUriTtlSeconds * 1000
    });

    return jsonResult(
      { request_uri: requestUri, expires_in: this.ports.config.requestUriTtlSeconds },
      { status: 201 }
    );
  }
}

export class GetConsentUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(parameters: OAuthParameters): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const oauthKey = required(parameters, "oauth_key");
    if (!oauthKey) return springParameterErrorResult("oauth_key");

    const authRequest = this.ports.state.getAuthorizationRequest(oauthKey);
    if (!authRequest) {
      return oauthErrorResult("invalid_request", "OAuth 2.0 Parameter: oauth_key", {
        errorUri: this.ports.config.authorizationErrorUri
      });
    }

    const client = this.ports.state.getClient(authRequest.clientId);
    return jsonResult({
      consent_required: authRequest.consentRequired,
      client_name: client?.clientName ?? authRequest.clientId,
      scopes: splitScope(authRequest.scope)
    });
  }
}

export class GetAuthDetailsUseCase {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async execute(body: AuthDetailsBody | null): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    if (!body?.oauth_key) return springParameterErrorResult("oauth_key");
    if (!body.auth_jwt) return springParameterErrorResult("auth_jwt");

    const authRequest = this.ports.state.getAuthorizationRequest(body.oauth_key);
    if (!authRequest) return springParameterErrorResult("oauth_key");

    const authPayload = this.ports.jwt.decode(body.auth_jwt);
    if (!authPayload || this.ports.jwt.isExpired(authPayload)) {
      return oauthErrorResult("invalid_request", "OAuth 2.0 Parameter: auth_jwt", {
        errorUri: this.ports.config.authorizationErrorUri
      });
    }

    return jsonResult({
      client_id: authRequest.clientId,
      authorization_details: authRequest.authorizationDetails ?? []
    });
  }
}

export class CompleteUserAuthorizationUseCase {
  private readonly clientAuthentication: ClientAuthenticationService;
  private readonly auditEvents: AuditEventService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.clientAuthentication = new ClientAuthenticationService(ports);
    this.auditEvents = new AuditEventService(ports);
  }

  async execute(request: OAuthRequestDto<UserAuthorizeBody | null>): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const body = request.body;
    if (!body?.oauth_key) return springParameterErrorResult("oauth_key");
    if (!body.user_jwt) return springParameterErrorResult("user_jwt");

    const authRequest = this.ports.state.getAuthorizationRequest(body.oauth_key);
    if (!authRequest) return springParameterErrorResult("oauth_key");

    const oauthClient = this.ports.state.getClient(authRequest.clientId);
    const providerId = oauthClient?.oauthAuthenticationProvider;
    const provider = providerId
      ? this.ports.state.getAuthenticationProvider(providerId)
      : undefined;
    if (!oauthClient || !provider) {
      await this.auditEvents.recordAuthenticationFailure(
        authRequest.oauthFlowId,
        authRequest.clientId,
        "authentication_provider_not_configured"
      );
      return oauthErrorResult(
        "invalid_request",
        "OAuth authentication provider is not configured",
        { errorUri: this.ports.config.authorizationErrorUri }
      );
    }

    const userHeader = this.ports.jwt.decodeHeader(body.user_jwt);
    const userPayload = this.ports.jwt.decode<TokenClaims & JwtPayload>(body.user_jwt);
    const audiences = this.ports.jwt.normalizeAudience(userPayload?.aud);
    const issuedAt = typeof userPayload?.iat === "number" ? userPayload.iat : undefined;
    const expiresAt = typeof userPayload?.exp === "number" ? userPayload.exp : undefined;
    const effectiveMaxTtlSeconds = Math.min(
      this.ports.config.authenticationProviderJwtMaxTtlSeconds,
      provider.userJwtMaxTtlSeconds
    );
    const providerJwks = await this.clientAuthentication.resolveAuthenticationProviderJwks(provider);
    const userJwtIsValid =
      userHeader?.alg === "RS256" &&
      Boolean(userHeader.kid) &&
      Boolean(userPayload) &&
      Boolean(stringClaim(userPayload?.sub)) &&
      issuedAt !== undefined &&
      issuedAt <= this.ports.jwt.nowSeconds() + provider.clockSkewSeconds &&
      expiresAt !== undefined &&
      expiresAt > issuedAt &&
      expiresAt - issuedAt <= effectiveMaxTtlSeconds &&
      !this.ports.jwt.isExpired(userPayload!, provider.clockSkewSeconds) &&
      userPayload?.iss === provider.issuer &&
      audiences.includes(request.baseUrl) &&
      Boolean(providerJwks) &&
      this.ports.jwt.verifySignature(body.user_jwt, providerJwks!);

    if (!userJwtIsValid || !userPayload) {
      await this.auditEvents.recordAuthenticationFailure(
        authRequest.oauthFlowId,
        authRequest.clientId,
        "invalid_user_jwt"
      );
      return oauthErrorResult("invalid_request", "OAuth 2.0 Parameter: user_jwt", {
        errorUri: this.ports.config.authorizationErrorUri
      });
    }

    const userId = stringClaim(userPayload.sub)!;
    const authenticationAudit = await this.ports.audit.record({
      auditType: "user_authenticated",
      auditStatus: "SUCCESS",
      oauthFlowId: authRequest.oauthFlowId,
      details: { userId, clientId: authRequest.clientId }
    });
    this.ports.loggers.token.info("User authenticated", {
      userId,
      clientId: authRequest.clientId,
      ...this.ports.audit.correlation(authenticationAudit),
      tags: ["oauth", "authentication"]
    });

    const authorizedScope = constrainUserScope(authRequest.scope, stringClaim(userPayload.scope));
    if (!authorizedScope) {
      return oauthErrorResult("invalid_scope", "OAuth 2.0 Parameter: scope", {
        errorUri: this.ports.config.authorizationErrorUri
      });
    }

    const code = this.ports.jwt.randomToken(32);
    const authorizationCode: AuthorizationCode = {
      code,
      oauthFlowId: authRequest.oauthFlowId,
      clientId: authRequest.clientId,
      redirectUri: authRequest.redirectUri,
      scope: authorizedScope,
      state: authRequest.state,
      codeChallenge: authRequest.codeChallenge,
      codeChallengeMethod: authRequest.codeChallengeMethod,
      nonce: authRequest.nonce,
      authorizationDetails: authRequest.authorizationDetails,
      userClaims: userPayload,
      expiresAt: Date.now() + this.ports.config.authorizationCodeTtlSeconds * 1000,
      consumed: false
    };

    await this.ports.state.deleteAuthorizationRequest(body.oauth_key);
    await this.ports.state.saveAuthorizationCode(authorizationCode);

    const codeHash = this.ports.audit.hash(code);
    const codeAudit = await this.ports.audit.record({
      auditType: "authorization_code_issued",
      auditStatus: "SUCCESS",
      oauthFlowId: authRequest.oauthFlowId,
      details: {
        clientId: authRequest.clientId,
        userId,
        authorizationCodeHash: codeHash
      }
    });
    this.ports.loggers.token.info("Authorization code issued", {
      clientId: authRequest.clientId,
      authorizationCodeHash: codeHash,
      ...this.ports.audit.correlation(codeAudit),
      tags: ["oauth", "authorization-code"]
    });

    return jsonResult({
      client_id: authRequest.clientId,
      code,
      state: authRequest.state,
      expires_in: this.ports.config.authorizationCodeTtlSeconds,
      redirect_uri: authRequest.redirectUri
    });
  }
}

export class HandleUserErrorUseCase {
  private readonly auditEvents: AuditEventService;

  constructor(private readonly ports: OAuthApplicationPorts) {
    this.auditEvents = new AuditEventService(ports);
  }

  async execute(request: OAuthRequestDto<UserErrorBody | null>): Promise<OAuthResponseDto> {
    await this.ports.maintenance.cleanup();
    const body = request.body;
    if (!body?.oauth_key) return springParameterErrorResult("oauth_key");
    if (!body.error_jwt) return springParameterErrorResult("error_jwt");

    const authRequest = this.ports.state.getAuthorizationRequest(body.oauth_key);
    if (!authRequest) return springParameterErrorResult("oauth_key");

    const errorPayload = this.ports.jwt.decode<TokenClaims & JwtPayload>(body.error_jwt);
    if (!errorPayload || this.ports.jwt.isExpired(errorPayload)) {
      await this.auditEvents.recordAuthenticationFailure(
        authRequest.oauthFlowId,
        authRequest.clientId,
        "invalid_error_jwt"
      );
      return springParameterErrorResult("error_jwt");
    }

    await this.auditEvents.recordAuthenticationFailure(
      authRequest.oauthFlowId,
      authRequest.clientId,
      stringClaim(errorPayload.error) ?? "invalid_credentials"
    );

    const issuedAt = this.ports.jwt.nowSeconds();
    const response = await this.ports.jwt.sign({
      jti: this.ports.jwt.jwtId(),
      iss: request.baseUrl,
      aud: authRequest.clientId,
      iat: issuedAt,
      exp: issuedAt + this.ports.config.authorizationCodeTtlSeconds,
      sub: stringClaim(errorPayload.sub) ?? "subject",
      error: stringClaim(errorPayload.error) ?? "access_denied",
      error_description:
        stringClaim(errorPayload.error_description) ?? "OAuth 2.0 Parameter: user",
      error_uri:
        stringClaim(errorPayload.error_uri) ?? this.ports.config.authorizationErrorUri
    });

    return jsonResult({
      client_id: authRequest.clientId,
      redirect_uri: authRequest.redirectUri,
      response_mode: authRequest.responseMode ?? "query.jwt",
      response
    });
  }
}

function validateAuthorizationParams(
  parameters: OAuthParameters,
  redirectOnClientErrors: boolean,
  ports: OAuthApplicationPorts,
  preAuthenticatedClient?: OAuthClient
):
  | { ok: true; client: OAuthClient; redirectUri: string; scope: string }
  | { ok: false; response: OAuthResponseDto; reasonCode: string; parameter?: string } {
  const responseType = required(parameters, "response_type");
  if (!responseType) {
    return {
      ok: false,
      response: springParameterErrorResult("response_type", { authEndpoint: true }),
      reasonCode: "missing_response_type",
      parameter: "response_type"
    };
  }
  if (responseType !== "code") {
    return {
      ok: false,
      response: oauthErrorResult(
        "unsupported_response_type",
        "OAuth 2.0 Parameter: response_type",
        { errorUri: ports.config.authorizationErrorUri }
      ),
      reasonCode: "unsupported_response_type",
      parameter: "response_type"
    };
  }

  const clientId = parameters.client_id ?? preAuthenticatedClient?.clientId;
  if (!clientId) {
    return {
      ok: false,
      response: springParameterErrorResult("client_id", { authEndpoint: true }),
      reasonCode: "missing_client_id",
      parameter: "client_id"
    };
  }

  const client = preAuthenticatedClient ?? ports.state.getClient(clientId);
  if (!client) {
    return {
      ok: false,
      response: springParameterErrorResult("client_id", { authEndpoint: true }),
      reasonCode: "unknown_client",
      parameter: "client_id"
    };
  }
  if (!client.grantTypes.includes("authorization_code")) {
    return {
      ok: false,
      response: oauthErrorResult(
        "unauthorized_client",
        "OAuth 2.0 Parameter: response_type",
        { errorUri: ports.config.authorizationErrorUri }
      ),
      reasonCode: "authorization_code_grant_not_allowed",
      parameter: "response_type"
    };
  }

  const redirectUri = parameters.redirect_uri ?? client.redirectUris[0];
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return {
      ok: false,
      response: springParameterErrorResult("redirect_uri", { authEndpoint: true }),
      reasonCode: "invalid_redirect_uri",
      parameter: "redirect_uri"
    };
  }

  const scope = normalizeRequestedScope(parameters.scope, client, ports.config, true);
  if (!scope.ok) {
    return {
      ok: false,
      response: redirectOnClientErrors
        ? redirectErrorResult(
            redirectUri,
            "invalid_scope",
            "OAuth 2.0 Parameter: scope",
            parameters.state
          )
        : scope.response,
      reasonCode: "invalid_scope",
      parameter: "scope"
    };
  }

  if (client.requirePkce && !parameters.code_challenge) {
    return {
      ok: false,
      response: springParameterErrorResult("code_challenge", { authEndpoint: true }),
      reasonCode: "missing_code_challenge",
      parameter: "code_challenge"
    };
  }
  if (client.requirePkce && parameters.code_challenge_method !== "S256") {
    return {
      ok: false,
      response: springParameterErrorResult("code_challenge_method", { authEndpoint: true }),
      reasonCode: "invalid_code_challenge_method",
      parameter: "code_challenge_method"
    };
  }

  return { ok: true, client, redirectUri, scope: scope.value };
}

function paramsWithRequestUri(
  parameters: OAuthParameters,
  ports: OAuthApplicationPorts
): OAuthParameters {
  const requestUri = parameters.request_uri;
  if (!requestUri) return { ...parameters };

  const pushed = ports.state.getPushedRequest(requestUri);
  if (!pushed || pushed.expiresAt <= Date.now()) return { ...parameters };

  return {
    ...pushed.params,
    ...Object.fromEntries(
      Object.entries(parameters).filter(([key]) => key !== "request_uri")
    )
  };
}
