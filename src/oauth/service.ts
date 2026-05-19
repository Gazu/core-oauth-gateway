import type { NextRequest } from "next/server";
import { verifyClientSecret } from "./client-secrets";
import { rememberClientAssertionJti } from "./client-assertions";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  AUTH_CODE_TTL_SECONDS,
  AUTH_PROVIDER_LOGIN_URL,
  CLIENT_ASSERTION_TYPE,
  JWT_BEARER_GRANT,
  JWT_BEARER_GRANT_COMPAT,
  PASSWORD_GRANT_ENABLED,
  PASSWORD_GRANT_USERS_JSON,
  REQUEST_URI_TTL_SECONDS,
  RFC6749_AUTH_ERROR_URI,
  RFC6749_TOKEN_ERROR_URI,
  RFC7636_ERROR_URI,
  REFRESH_TOKEN_TTL_SECONDS,
  SUPPORTED_SCOPES,
  TOKEN_EXCHANGE_GRANT
} from "./config";
import {
  baseUrlFromRequest,
  emptyResponse,
  invalidClient,
  jsonResponse,
  oauthError,
  paramsToRecord,
  readForm,
  readJson,
  redirectWithOAuthError,
  springParameterError
} from "./http";
import {
  decodeJwt,
  decodeJwtHeader,
  isJwtExpired,
  jwtId,
  normalizeAudience,
  nowSeconds,
  publicJwkSet,
  randomToken,
  s256,
  signJwt,
  tokenHash,
  verifyJwtSignature
} from "./jwt";
import { clientAuthLogger, tokenFingerprint, tokenLogger } from "./logger";
import {
  cleanupExpiredRecords,
  findStoredAccessToken,
  findStoredRefreshToken,
  getStore,
  listStoredTokens,
  persistStore,
  revokeStoredToken,
  revokeStoredTokenById,
  revokeStoredTokensBySubject
} from "./store";
import type {
  AuthorizationCode,
  AuthorizationRequest,
  JwtPayload,
  OAuthClient,
  OAuthJwks,
  StoredAccessToken,
  TokenClaims
} from "./types";

type ClientAuth =
  | {
      ok: true;
      client: OAuthClient;
      method: "client_secret_basic" | "private_key_jwt" | "none";
      assertionPayload?: JwtPayload;
    }
  | {
      ok: false;
      response: Response;
    };

type TokenSetInput = {
  client: OAuthClient;
  subject: string;
  scope: string;
  baseUrl: string;
  claims?: TokenClaims;
  nonce?: string;
  authorizationDetails?: unknown;
  includeRefreshToken?: boolean;
  includeIdToken?: boolean;
};

const PASSWORD_USERS = loadPasswordUsers();

export async function openIdConfigurationHandler(request: NextRequest): Promise<Response> {
  const baseUrl = baseUrlFromRequest(request);
  const tokenEndpoint = `${baseUrl}/oauth2/v1/token`;

  return jsonResponse({
    request_parameter_supported: true,
    authorization_signed_response_alg: ["RS256"],
    pushed_authorization_request_endpoint: `${baseUrl}/oauth2/v1/authorize/par`,
    scopes_supported: SUPPORTED_SCOPES,
    backchannel_logout_supported: true,
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth2/v1/authorize`,
    service_documentation: "https://docs.spring.io/spring-authorization-server/reference/getting-started.html",
    claims_supported: ["sub", "email", "scope", "profile", "idt", "userId", "user_id"],
    require_pushed_authorization_requests: false,
    token_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic"],
    response_modes_supported: ["query", "query.jwt", "jwt"],
    backchannel_logout_session_supported: true,
    token_endpoint: tokenEndpoint,
    response_types_supported: ["code"],
    revocation_endpoint_auth_signing_alg_values_supported: [
      "RS256",
      "RS384",
      "RS512",
      "ES256",
      "ES384",
      "ES512"
    ],
    revocation_endpoint_auth_methods_supported: ["private_key_jwt", "client_secret_basic"],
    request_uri_parameter_supported: false,
    grant_types_supported: [
      "authorization_code",
      "client_credentials",
      ...(PASSWORD_GRANT_ENABLED ? ["password"] : []),
      "refresh_token",
      JWT_BEARER_GRANT,
      TOKEN_EXCHANGE_GRANT
    ],
    revocation_endpoint: `${baseUrl}/oauth2/v1/revoke`,
    introspection_endpoint: `${baseUrl}/oauth2/v1/introspect`,
    userinfo_endpoint: `${baseUrl}/oauth2/v1/userinfo`,
    token_endpoint_auth_signing_alg_values_supported: [
      "RS256",
      "RS384",
      "RS512",
      "ES256",
      "ES384",
      "ES512"
    ],
    code_challenge_methods_supported: ["S256"],
    jwks_uri: `${baseUrl}/oauth2/v1/certs`,
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256", "ES256"]
  });
}

export async function authorizeHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const baseUrl = baseUrlFromRequest(request);
  const params = await paramsWithRequestUri(request.nextUrl.searchParams);
  const validation = validateAuthorizationParams(params, true);

  if (!validation.ok) return validation.response;

  const oauthKey = randomToken(11);
  const expiresAt = Date.now() + AUTH_CODE_TTL_SECONDS * 1000;
  const authRequest: AuthorizationRequest = {
    oauthKey,
    clientId: validation.client.clientId,
    redirectUri: validation.redirectUri,
    scope: validation.scope,
    state: optional(params, "state"),
    codeChallenge: optional(params, "code_challenge"),
    codeChallengeMethod: optional(params, "code_challenge_method"),
    nonce: optional(params, "nonce"),
    responseMode: optional(params, "response_mode"),
    authorizationDetails: parseAuthorizationDetails(optional(params, "authorization_details")),
    consentRequired: validation.client.requireConsent ?? false,
    clientMetadata: validation.client.clientMetadata,
    params: paramsToRecord(params),
    expiresAt
  };

  getStore().authorizationRequests.set(oauthKey, authRequest);
  await persistStore();

  const issuedAt = nowSeconds();
  const oauthKeySignature = await signJwt({
    jti: jwtId(),
    iat: issuedAt,
    exp: issuedAt + AUTH_CODE_TTL_SECONDS,
    iss: baseUrl,
    aud: AUTH_PROVIDER_LOGIN_URL,
    oauth_key: oauthKey,
    client_id: validation.client.clientId,
    consent_required: authRequest.consentRequired,
    scope: validation.scope,
    redirect_uri: validation.redirectUri,
    state: authRequest.state,
    client_metadata: validation.client.clientMetadata,
    ui_locales: optional(params, "ui_locales"),
    acr_values: optional(params, "acr_values")
  });

  const loginUrl = new URL(AUTH_PROVIDER_LOGIN_URL);
  loginUrl.searchParams.set("oauth_key", oauthKey);
  loginUrl.searchParams.set("oauth_key_signature", oauthKeySignature);

  return jsonResponse(
    {},
    {
      status: 302,
      headers: {
        Location: loginUrl.toString()
      }
    }
  );
}

export async function pushedAuthorizeHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const baseUrl = baseUrlFromRequest(request);
  const params = await readForm(request);
  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: true,
    required: false
  });
  const hintedClientId = params.get("client_id");
  const hintedClient = hintedClientId ? getStore().clients.get(hintedClientId) : undefined;

  if (!clientAuth.ok && !params.get("client_id")) return clientAuth.response;
  if (hintedClient?.type === "confidential" && !clientAuth.ok) return invalidClient();
  const validation = validateAuthorizationParams(params, false, clientAuth.ok ? clientAuth.client : undefined);
  if (!validation.ok) return validation.response;

  const requestUri = `urn:ietf:params:request_uri:${randomToken(32)}`;
  getStore().pushedRequests.set(requestUri, {
    requestUri,
    params: paramsToRecord(params),
    expiresAt: Date.now() + REQUEST_URI_TTL_SECONDS * 1000
  });
  await persistStore();

  return jsonResponse(
    {
      request_uri: requestUri,
      expires_in: REQUEST_URI_TTL_SECONDS
    },
    { status: 201 }
  );
}

export async function consentHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const oauthKey = request.nextUrl.searchParams.get("oauth_key");
  if (!oauthKey) return springParameterError("oauth_key");

  const authRequest = getStore().authorizationRequests.get(oauthKey);
  if (!authRequest) {
    return oauthError("invalid_request", "OAuth 2.0 Parameter: oauth_key", {
      errorUri: RFC6749_AUTH_ERROR_URI
    });
  }

  const client = getStore().clients.get(authRequest.clientId);
  return jsonResponse({
    consent_required: authRequest.consentRequired,
    client_name: client?.clientName ?? authRequest.clientId,
    scopes: splitScope(authRequest.scope)
  });
}

export async function authDetailsHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const body = await readJson<{ oauth_key?: string; auth_jwt?: string }>(request);
  if (!body?.oauth_key) return springParameterError("oauth_key");
  if (!body.auth_jwt) return springParameterError("auth_jwt");

  const authRequest = getStore().authorizationRequests.get(body.oauth_key);
  if (!authRequest) return springParameterError("oauth_key");

  const authPayload = decodeJwt(body.auth_jwt);
  if (!authPayload || isJwtExpired(authPayload)) {
    return oauthError("invalid_request", "OAuth 2.0 Parameter: auth_jwt", {
      errorUri: RFC6749_AUTH_ERROR_URI
    });
  }

  return jsonResponse({
    client_id: authRequest.clientId,
    authorization_details: authRequest.authorizationDetails ?? []
  });
}

export async function userAuthorizeHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const body = await readJson<{ oauth_key?: string; user_jwt?: string }>(request);
  if (!body?.oauth_key) return springParameterError("oauth_key");
  if (!body.user_jwt) return springParameterError("user_jwt");

  const authRequest = getStore().authorizationRequests.get(body.oauth_key);
  if (!authRequest) return springParameterError("oauth_key");

  const userPayload = decodeJwt<TokenClaims & JwtPayload>(body.user_jwt);
  if (!userPayload || isJwtExpired(userPayload)) {
    return oauthError("invalid_request", "OAuth 2.0 Parameter: user_jwt", {
      errorUri: RFC6749_AUTH_ERROR_URI
    });
  }

  const code = randomToken(32);
  const authorizationCode: AuthorizationCode = {
    code,
    clientId: authRequest.clientId,
    redirectUri: authRequest.redirectUri,
    scope: typeof userPayload.scope === "string" ? userPayload.scope : authRequest.scope,
    state: authRequest.state,
    codeChallenge: authRequest.codeChallenge,
    codeChallengeMethod: authRequest.codeChallengeMethod,
    nonce: authRequest.nonce,
    authorizationDetails: authRequest.authorizationDetails,
    userClaims: userPayload,
    expiresAt: Date.now() + AUTH_CODE_TTL_SECONDS * 1000,
    consumed: false
  };

  getStore().authorizationCodes.set(code, authorizationCode);
  await persistStore();

  return jsonResponse({
    client_id: authRequest.clientId,
    code,
    state: authRequest.state,
    expires_in: AUTH_CODE_TTL_SECONDS,
    redirect_uri: authRequest.redirectUri
  });
}

export async function userErrorHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const baseUrl = baseUrlFromRequest(request);
  const body = await readJson<{ oauth_key?: string; error_jwt?: string }>(request);
  if (!body?.oauth_key) return springParameterError("oauth_key");
  if (!body.error_jwt) return springParameterError("error_jwt");

  const authRequest = getStore().authorizationRequests.get(body.oauth_key);
  if (!authRequest) return springParameterError("oauth_key");

  const errorPayload = decodeJwt<TokenClaims & JwtPayload>(body.error_jwt);
  if (!errorPayload || isJwtExpired(errorPayload)) {
    return springParameterError("error_jwt");
  }

  const issuedAt = nowSeconds();
  const response = await signJwt({
    jti: jwtId(),
    iss: baseUrl,
    aud: authRequest.clientId,
    iat: issuedAt,
    exp: issuedAt + AUTH_CODE_TTL_SECONDS,
    sub: stringClaim(errorPayload.sub) ?? "subject",
    error: stringClaim(errorPayload.error) ?? "access_denied",
    error_description: stringClaim(errorPayload.error_description) ?? "OAuth 2.0 Parameter: user",
    error_uri: stringClaim(errorPayload.error_uri) ?? RFC6749_AUTH_ERROR_URI
  });

  return jsonResponse({
    client_id: authRequest.clientId,
    redirect_uri: authRequest.redirectUri,
    response_mode: authRequest.responseMode ?? "query.jwt",
    response
  });
}

export async function tokenHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const baseUrl = baseUrlFromRequest(request);
  const params = await readForm(request);
  const grantType = required(params, "grant_type");

  if (!grantType) return springParameterError("grant_type");

  switch (grantType) {
    case "client_credentials":
      return clientCredentialsGrant(request, params, baseUrl);
    case "password":
      return passwordGrant(request, params, baseUrl);
    case "authorization_code":
      return authorizationCodeGrant(request, params, baseUrl);
    case JWT_BEARER_GRANT:
    case JWT_BEARER_GRANT_COMPAT:
      return jwtBearerGrant(params, baseUrl);
    case "refresh_token":
      return refreshTokenGrant(request, params, baseUrl);
    case TOKEN_EXCHANGE_GRANT:
      return tokenExchangeGrant(request, params, baseUrl);
    default:
      return oauthError("unsupported_grant_type", `OAuth 2.0 Parameter: grant_type`, {
        errorUri: RFC6749_TOKEN_ERROR_URI
      });
  }
}

export async function tokenInfoHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  const token = required(params, "token");
  if (!token) return springParameterError("token");

  const stored = await findStoredAccessToken(token);
  if (stored && !stored.revoked && stored.expiresAt > Date.now()) {
    tokenLogger.info((event) => {
      event
        .message("Opaque token exchanged for signed JWT")
        .tag("oauth")
        .tag("tokeninfo")
        .with("tokenHash", tokenFingerprint(token))
        .with("clientId", stored.clientId)
        .with("subject", stored.subject)
        .with("scope", stored.scope)
        .with("expiresAt", stored.expiresAt);
    });
    return jsonResponse({
      access_token: stored.jwt
    });
  }

  if (decodeJwt(token)) {
    tokenLogger.info((event) => {
      event
        .message("JWT tokeninfo passthrough")
        .tag("oauth")
        .tag("tokeninfo")
        .with("tokenHash", tokenFingerprint(token));
    });
    return jsonResponse({
      access_token: token
    });
  }

  return oauthError("invalid_token", "The access token is invalid", {
    errorUri: "https://datatracker.ietf.org/doc/html/rfc6750#section-3.1"
  });
}

export async function introspectionHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  const token = required(params, "token");
  if (!token) return springParameterError("token");

  const stored = await findStoredAccessToken(token);
  if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
    tokenLogger.info((event) => {
      event
        .message("Token introspection inactive")
        .tag("oauth")
        .tag("introspection")
        .with("tokenHash", tokenFingerprint(token));
    });
    return jsonResponse({ active: false });
  }

  tokenLogger.info((event) => {
    event
      .message("Token introspection active")
      .tag("oauth")
      .tag("introspection")
      .with("tokenHash", tokenFingerprint(token))
      .with("clientId", stored.clientId)
      .with("subject", stored.subject)
      .with("scope", stored.scope);
  });

  return jsonResponse({
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

export async function userInfoHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const token = await bearerOrFormToken(request);
  if (!token) {
    return oauthError("invalid_request", "OAuth 2.0 Parameter: access_token", {
      status: 401,
      errorUri: "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError",
      headers: {
        "WWW-Authenticate": 'Bearer error="invalid_request", error_description="OAuth 2.0 Parameter: access_token"'
      }
    });
  }

  const stored = await findStoredAccessToken(token);
  if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
    tokenLogger.warn((event) => {
      event
        .message("UserInfo rejected invalid token")
        .tag("oauth")
        .tag("userinfo")
        .with("tokenHash", tokenFingerprint(token));
    });
    return oauthError("invalid_token", "The access token is invalid", {
      status: 401,
      errorUri: "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError",
      headers: {
        "WWW-Authenticate": 'Bearer error="invalid_token", error_description="The access token is invalid"'
      }
    });
  }

  tokenLogger.info((event) => {
    event
      .message("UserInfo returned claims")
      .tag("oauth")
      .tag("userinfo")
      .with("tokenHash", tokenFingerprint(token))
      .with("clientId", stored.clientId)
      .with("subject", stored.subject)
      .with("scope", stored.scope);
  });

  return jsonResponse({
    sub: stored.subject,
    profile: objectClaim(stored.claims.profile) ?? {},
    scope: stored.scope,
    client_id: stored.clientId
  });
}

export async function certsHandler(): Promise<Response> {
  return jsonResponse({
    keys: await publicJwkSet()
  });
}

export async function revokeHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  const token = required(params, "token");
  if (!token) return springParameterError("token");

  const revoked = await revokeStoredToken(token);
  tokenLogger.info((event) => {
    event
      .message("Token revocation requested")
      .tag("oauth")
      .tag("revocation")
      .with("tokenHash", tokenFingerprint(token))
      .with("revoked", revoked);
  });

  return emptyResponse();
}

export async function listAccessTokensHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  const assertion = required(params, "assertion");
  if (!assertion) return springParameterError("assertion");

  const assertionPayload = decodeJwt(assertion);
  if (!assertionPayload || isJwtExpired(assertionPayload)) {
    return springParameterError("assertion");
  }

  const clientFilter = optional(params, "client_id")
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const requiredClaims = parseRequiredClaims(optional(params, "required_claims"));
  const { accessTokens, refreshTokens } = await listStoredTokens();
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

  return jsonResponse(response);
}

export async function revokeByIdHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  if (!required(params, "assertion")) return springParameterError("assertion");
  const tokenId = required(params, "token_id");
  if (!tokenId) return springParameterError("token_id");

  await revokeStoredTokenById(tokenId);

  return emptyResponse();
}

export async function revokeBySubjectHandler(request: NextRequest): Promise<Response> {
  await cleanupExpiredRecords();
  const params = await readForm(request);
  const assertion = required(params, "assertion");
  if (!assertion) return springParameterError("assertion");

  const assertionPayload = decodeJwt(assertion);
  if (!assertionPayload || isJwtExpired(assertionPayload)) {
    return springParameterError("assertion");
  }

  const subject = optional(params, "sub") ?? stringClaim(assertionPayload.sub);
  const clientFilter = optional(params, "client_id")
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const deletedTokenCount = await revokeStoredTokensBySubject(subject, clientFilter);

  return jsonResponse({ deletedTokenCount });
}

async function clientCredentialsGrant(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string
): Promise<Response> {
  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: false,
    required: true
  });
  if (!clientAuth.ok) return clientAuth.response;

  const client = clientAuth.client;
  if (!client.grantTypes.includes("client_credentials")) {
    return oauthError("unauthorized_client", "OAuth 2.0 Parameter: grant_type", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const scope = normalizeRequestedScope(params.get("scope"), client);
  if (!scope.ok) return scope.response;

  return jsonResponse(
    await createTokenSet({
      client,
      subject: client.clientId,
      scope: scope.value,
      baseUrl
    })
  );
}

async function passwordGrant(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string
): Promise<Response> {
  if (!PASSWORD_GRANT_ENABLED) {
    return oauthError("unsupported_grant_type", "Password grant is disabled", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const username = required(params, "username");
  const password = required(params, "password");
  if (!username) return springParameterError("username");
  if (!password) return springParameterError("password");

  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: false,
    required: true
  });
  if (!clientAuth.ok) return clientAuth.response;

  const user = PASSWORD_USERS[username];
  if (!user || user.password !== password) {
    return oauthError("invalid_grant", "Bad credentials", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const scope = normalizeRequestedScope(params.get("scope"), clientAuth.client);
  if (!scope.ok) return scope.response;

  return jsonResponse(
    await createTokenSet({
      client: clientAuth.client,
      subject: stringClaim(user.claims.sub) ?? username,
      scope: scope.value,
      baseUrl,
      claims: user.claims,
      includeRefreshToken: true,
      includeIdToken: splitScope(scope.value).includes("openid")
    })
  );
}

async function authorizationCodeGrant(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string
): Promise<Response> {
  const code = required(params, "code");
  if (!code) return springParameterError("code");

  const store = getStore();
  const authorizationCode = store.authorizationCodes.get(code);
  if (!authorizationCode || authorizationCode.consumed || authorizationCode.expiresAt <= Date.now()) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: code", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const client = store.clients.get(authorizationCode.clientId);
  if (!client) return invalidClient();

  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: true,
    required: client.type === "confidential",
    expectedClientId: client.clientId
  });
  if (!clientAuth.ok) return clientAuth.response;

  const redirectUri = params.get("redirect_uri");
  if (redirectUri && redirectUri !== authorizationCode.redirectUri) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: redirect_uri", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  if (authorizationCode.codeChallenge) {
    const verifier = params.get("code_verifier");
    if (!verifier) {
      return springParameterError("code_verifier");
    }
    if (authorizationCode.codeChallengeMethod !== "S256" || s256(verifier) !== authorizationCode.codeChallenge) {
      return oauthError("invalid_grant", "OAuth 2.0 Parameter: code_verifier", {
        errorUri: RFC7636_ERROR_URI
      });
    }
  }

  authorizationCode.consumed = true;

  return jsonResponse(
    await createTokenSet({
      client,
      subject: stringClaim(authorizationCode.userClaims.sub) ?? "subject",
      scope: authorizationCode.scope,
      baseUrl,
      claims: authorizationCode.userClaims,
      nonce: authorizationCode.nonce,
      authorizationDetails: authorizationCode.authorizationDetails,
      includeRefreshToken: true,
      includeIdToken: splitScope(authorizationCode.scope).includes("openid")
    })
  );
}

async function jwtBearerGrant(params: URLSearchParams, baseUrl: string): Promise<Response> {
  const assertion = required(params, "assertion");
  if (!assertion) return springParameterError("assertion");

  const header = decodeJwtHeader(assertion);
  const payload = decodeJwt<TokenClaims & JwtPayload>(assertion);
  if (!header || header.alg !== "RS256" || !header.kid || !payload || isJwtExpired(payload)) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: assertion", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }
  if (!payload.jti || typeof payload.jti !== "string") {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: jti", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const audiences = normalizeAudience(payload.aud);
  if (audiences.length && !audiences.includes(baseUrl) && !audiences.includes(`${baseUrl}/oauth2/v1/token`)) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: aud", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const issuerClient = typeof payload.iss === "string" ? getStore().clients.get(payload.iss) : undefined;
  const client = issuerClient;
  if (!client) return invalidClient();
  if (!client.grantTypes.includes(JWT_BEARER_GRANT) && !client.grantTypes.includes(JWT_BEARER_GRANT_COMPAT)) {
    return oauthError("unauthorized_client", "OAuth 2.0 Parameter: grant_type", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const clientJwks = await resolveClientJwks(client);
  if (!clientJwks || !verifyJwtSignature(assertion, clientJwks)) {
    clientAuthLogger.warn((event) => {
      event
        .message("JWT bearer assertion signature validation failed")
        .tag("oauth")
        .tag("jwt-bearer")
        .with("clientId", client.clientId)
        .with("kid", header.kid);
    });
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: assertion", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }
  if (!(await rememberClientAssertionJti(client.clientId, payload.jti, payload.exp))) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: jti", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const scope = normalizeRequestedScope(params.get("scope") ?? stringClaim(payload.scope), client);
  if (!scope.ok) return scope.response;
  const subject = stringClaim(payload.sub) ?? client.clientId;

  return jsonResponse(
    await createTokenSet({
      client,
      subject,
      scope: scope.value,
      baseUrl,
      claims: payload
    })
  );
}

async function refreshTokenGrant(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string
): Promise<Response> {
  const refreshToken = required(params, "refresh_token");
  if (!refreshToken) return springParameterError("refresh_token");

  const stored = await findStoredRefreshToken(refreshToken);
  if (!stored || stored.revoked || stored.expiresAt <= Date.now()) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: refresh_token", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const client = getStore().clients.get(stored.clientId);
  if (!client) return invalidClient();
  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: true,
    required: client.type === "confidential",
    expectedClientId: client.clientId
  });
  if (!clientAuth.ok) return clientAuth.response;

  const scope = normalizeRequestedScope(params.get("scope") ?? stored.scope, client);
  if (!scope.ok) return scope.response;

  return jsonResponse(
    await createTokenSet({
      client,
      subject: stored.subject,
      scope: scope.value,
      baseUrl,
      claims: stored.userClaims,
      includeRefreshToken: true,
      includeIdToken: splitScope(scope.value).includes("openid")
    })
  );
}

async function tokenExchangeGrant(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string
): Promise<Response> {
  const clientAuth = await authenticateClient(request, params, baseUrl, {
    allowPublic: false,
    required: true
  });
  if (!clientAuth.ok) return clientAuth.response;

  const subjectToken = required(params, "subject_token");
  const subjectTokenType = required(params, "subject_token_type");
  if (!subjectToken) return springParameterError("subject_token");
  if (!subjectTokenType) return springParameterError("subject_token_type");

  const stored = await findStoredAccessToken(subjectToken);
  const decoded = stored ? decodeJwt<TokenClaims & JwtPayload>(stored.jwt) : decodeJwt<TokenClaims & JwtPayload>(subjectToken);
  if (!stored && !decoded) {
    return oauthError("invalid_grant", "OAuth 2.0 Parameter: subject_token", {
      errorUri: RFC6749_TOKEN_ERROR_URI
    });
  }

  const subject = stored?.subject ?? stringClaim(decoded?.sub) ?? clientAuth.client.clientId;
  const claims = stored?.claims ?? decoded ?? {};
  const scope = normalizeRequestedScope(params.get("scope") ?? stored?.scope ?? stringClaim(decoded?.scope), clientAuth.client);
  if (!scope.ok) return scope.response;

  return jsonResponse(
    await createTokenSet({
      client: clientAuth.client,
      subject,
      scope: scope.value,
      baseUrl,
      claims: {
        ...claims,
        audience: params.get("audience") ?? undefined
      },
      authorizationDetails: parseAuthorizationDetails(optional(params, "authorization_details"))
    })
  );
}

async function authenticateClient(
  request: NextRequest,
  params: URLSearchParams,
  baseUrl: string,
  options: {
    allowPublic: boolean;
    required: boolean;
    expectedClientId?: string;
  }
): Promise<ClientAuth> {
  const store = getStore();
  const basic = parseBasicAuth(request.headers.get("authorization"));
  if (basic) {
    const client = store.clients.get(basic.clientId);
    if (!client || !client.authMethods.includes("client_secret_basic") || !isClientSecretValid(client, basic.clientSecret)) {
      clientAuthLogger.warn((event) => {
        event
          .message("Client basic authentication failed")
          .tag("oauth")
          .tag("client-auth")
          .with("clientId", basic.clientId)
          .with("method", "client_secret_basic");
      });
      return { ok: false, response: invalidClient() };
    }
    if (options.expectedClientId && options.expectedClientId !== client.clientId) {
      return { ok: false, response: invalidClient() };
    }
    clientAuthLogger.info((event) => {
      event
        .message("Client authenticated")
        .tag("oauth")
        .tag("client-auth")
        .with("clientId", client.clientId)
        .with("method", "client_secret_basic");
    });
    return { ok: true, client, method: "client_secret_basic" };
  }

  const assertion = params.get("client_assertion");
  const assertionType = params.get("client_assertion_type");
  if (assertion || assertionType) {
    if (assertionType !== CLIENT_ASSERTION_TYPE) {
      return { ok: false, response: springParameterError("client_assertion_type") };
    }
    if (!assertion) {
      return { ok: false, response: springParameterError("client_assertion") };
    }

    const header = decodeJwtHeader(assertion);
    const payload = decodeJwt(assertion);
    if (!header || header.alg !== "RS256" || !header.kid) {
      return { ok: false, response: invalidClient("Client assertion signature is invalid") };
    }
    if (!payload || isJwtExpired(payload)) {
      return { ok: false, response: invalidClient("Client assertion is invalid") };
    }

    const clientId = stringClaim(payload.iss) ?? stringClaim(payload.sub);
    const client = clientId ? store.clients.get(clientId) : undefined;
    if (!client || !client.authMethods.includes("private_key_jwt")) {
      return { ok: false, response: invalidClient() };
    }
    if (options.expectedClientId && options.expectedClientId !== client.clientId) {
      return { ok: false, response: invalidClient() };
    }
    if (payload.sub !== client.clientId || payload.iss !== client.clientId) {
      return { ok: false, response: invalidClient("Client assertion subject is invalid") };
    }
    if (!payload.jti || typeof payload.jti !== "string") {
      return { ok: false, response: invalidClient("Client assertion jti is required") };
    }

    const audiences = normalizeAudience(payload.aud);
    const currentRequestUrl = request.nextUrl.origin + request.nextUrl.pathname;
    if (
      audiences.length > 0 &&
      !audiences.includes(baseUrl) &&
      !audiences.includes(`${baseUrl}/oauth2/v1/token`) &&
      !audiences.includes(currentRequestUrl)
    ) {
      return { ok: false, response: invalidClient("Client assertion audience is invalid") };
    }

    const clientJwks = await resolveClientJwks(client);
    if (!clientJwks || !verifyJwtSignature(assertion, clientJwks)) {
      clientAuthLogger.warn((event) => {
        event
          .message("Client assertion signature validation failed")
          .tag("oauth")
          .tag("client-auth")
          .with("clientId", client.clientId)
          .with("method", "private_key_jwt")
          .with("kid", header.kid);
      });
      return { ok: false, response: invalidClient("Client assertion signature is invalid") };
    }

    if (!(await rememberClientAssertionJti(client.clientId, payload.jti, payload.exp))) {
      clientAuthLogger.warn((event) => {
        event
          .message("Client assertion replay rejected")
          .tag("oauth")
          .tag("client-auth")
          .with("clientId", client.clientId)
          .with("method", "private_key_jwt")
          .with("jti", payload.jti);
      });
      return { ok: false, response: invalidClient("Client assertion was already used") };
    }

    clientAuthLogger.info((event) => {
      event
        .message("Client authenticated")
        .tag("oauth")
        .tag("client-auth")
        .with("clientId", client.clientId)
        .with("method", "private_key_jwt")
        .with("kid", header.kid)
        .with("jti", payload.jti);
    });

    return {
      ok: true,
      client,
      method: "private_key_jwt",
      assertionPayload: payload
    };
  }

  const clientId = params.get("client_id");
  if (clientId) {
    const client = store.clients.get(clientId);
    if (!client) return { ok: false, response: invalidClient() };
    if (options.expectedClientId && options.expectedClientId !== client.clientId) {
      return { ok: false, response: invalidClient() };
    }
    if (client.type === "public" && options.allowPublic) {
      return { ok: true, client, method: "none" };
    }
    if (!options.required) return { ok: true, client, method: "none" };
  }

  if (options.required) return { ok: false, response: invalidClient() };

  return { ok: false, response: invalidClient() };
}

function isClientSecretValid(client: OAuthClient, providedSecret: string): boolean {
  if (client.clientSecretHash) return verifyClientSecret(providedSecret, client.clientSecretHash);
  return false;
}

async function resolveClientJwks(client: OAuthClient): Promise<OAuthJwks | null> {
  if (client.jwks?.keys?.length) return client.jwks;
  if (!client.jwksUri) return null;

  const response = await fetch(client.jwksUri, {
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) return null;

  const jwks = (await response.json()) as OAuthJwks;
  return Array.isArray(jwks.keys) ? jwks : null;
}

function validateAuthorizationParams(
  params: URLSearchParams,
  redirectOnClientErrors: boolean,
  preAuthenticatedClient?: OAuthClient
):
  | { ok: true; client: OAuthClient; redirectUri: string; scope: string }
  | { ok: false; response: Response } {
  const responseType = required(params, "response_type");
  if (!responseType) {
    return { ok: false, response: springParameterError("response_type", { authEndpoint: true }) };
  }
  if (responseType !== "code") {
    return {
      ok: false,
      response: oauthError("unsupported_response_type", "OAuth 2.0 Parameter: response_type", {
        errorUri: RFC6749_AUTH_ERROR_URI
      })
    };
  }

  const clientId = params.get("client_id") ?? preAuthenticatedClient?.clientId;
  if (!clientId) {
    return { ok: false, response: springParameterError("client_id", { authEndpoint: true }) };
  }

  const client = preAuthenticatedClient ?? getStore().clients.get(clientId);
  if (!client) {
    return { ok: false, response: springParameterError("client_id", { authEndpoint: true }) };
  }

  const redirectUri = params.get("redirect_uri") ?? client.redirectUris[0];
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, response: springParameterError("redirect_uri", { authEndpoint: true }) };
  }

  const scope = normalizeRequestedScope(params.get("scope"), client, true);
  if (!scope.ok) {
    if (redirectOnClientErrors) {
      return {
        ok: false,
        response: redirectWithOAuthError(
          redirectUri,
          "invalid_scope",
          "OAuth 2.0 Parameter: scope",
          params.get("state") ?? undefined
        )
      };
    }
    return { ok: false, response: scope.response };
  }

  if (client.requirePkce && params.get("code_challenge") && params.get("code_challenge_method") !== "S256") {
    return { ok: false, response: springParameterError("code_challenge_method", { authEndpoint: true }) };
  }

  return {
    ok: true,
    client,
    redirectUri,
    scope: scope.value
  };
}

async function paramsWithRequestUri(params: URLSearchParams): Promise<URLSearchParams> {
  const requestUri = params.get("request_uri");
  if (!requestUri) return new URLSearchParams(params);

  const pushed = getStore().pushedRequests.get(requestUri);
  if (!pushed || pushed.expiresAt <= Date.now()) return new URLSearchParams(params);

  const merged = new URLSearchParams(pushed.params);
  for (const [key, value] of params.entries()) {
    if (key !== "request_uri") merged.set(key, value);
  }
  return merged;
}

async function createTokenSet(input: TokenSetInput): Promise<Record<string, unknown>> {
  const now = nowSeconds();
  const issuedAt = now * 1000;
  const accessTokenTtlSeconds = input.client.accessTokenTtlSeconds ?? ACCESS_TOKEN_TTL_SECONDS;
  const refreshTokenTtlSeconds = input.client.refreshTokenTtlSeconds ?? REFRESH_TOKEN_TTL_SECONDS;
  const expiresAt = issuedAt + accessTokenTtlSeconds * 1000;
  const opaqueToken = randomToken(32);
  const tokenId = tokenHash(opaqueToken);
  const customClaims = cleanCustomClaims(input.claims ?? {});
  const accessPayload: JwtPayload = {
    ...customClaims,
    jti: tokenId,
    sub: input.subject,
    iss: input.baseUrl,
    iat: now,
    exp: now + accessTokenTtlSeconds,
    azp: input.client.clientId,
    client_id: input.client.clientId,
    scope: input.scope,
    client_metadata: input.client.clientMetadata ?? {}
  };
  const accessJwt = await signJwt(accessPayload);
  const accessToken = input.client.opaqueToken === false ? accessJwt : opaqueToken;
  const stored: StoredAccessToken = {
    token: accessToken,
    tokenId: tokenHash(accessToken),
    jwt: accessJwt,
    clientId: input.client.clientId,
    subject: input.subject,
    scope: input.scope,
    issuedAt,
    expiresAt,
    revoked: false,
    claims: accessPayload
  };
  getStore().accessTokens.set(accessToken, stored);

  const response: Record<string, unknown> = {
    access_token: accessToken,
    scope: input.scope,
    token_type: "Bearer",
    expires_in: accessTokenTtlSeconds
  };

  if (input.includeRefreshToken) {
    const refreshToken = randomToken(32);
    const refreshTokenId = tokenHash(refreshToken);
    getStore().refreshTokens.set(refreshToken, {
      token: refreshToken,
      tokenId: refreshTokenId,
      clientId: input.client.clientId,
      subject: input.subject,
      scope: input.scope,
      issuedAt,
      expiresAt: issuedAt + refreshTokenTtlSeconds * 1000,
      revoked: false,
      userClaims: input.claims ?? {}
    });
    response.refresh_token = refreshToken;
  }

  if (input.includeIdToken) {
    response.id_token = await createIdToken(input, now);
  }

  if (input.authorizationDetails) {
    response.authorization_details = input.authorizationDetails;
  }

  await persistStore();

  tokenLogger.info((event) => {
    event
      .message("Token set issued")
      .tag("oauth")
      .tag("token")
      .with("accessTokenHash", tokenId)
      .with("clientId", input.client.clientId)
      .with("subject", input.subject)
      .with("scope", input.scope)
      .with("expiresAt", expiresAt)
      .with("refreshTokenIssued", Boolean(response.refresh_token))
      .with("idTokenIssued", Boolean(response.id_token));
  });

  return response;
}

async function createIdToken(input: TokenSetInput, now: number): Promise<string> {
  const idt = objectClaim(input.claims?.idt);
  const subject = stringClaim(idt?.sub) ?? input.subject;
  return signJwt({
    ...idt,
    jti: jwtId(),
    sub: subject,
    iss: input.baseUrl,
    aud: input.client.clientId,
    iat: now,
    exp: now + (input.client.accessTokenTtlSeconds ?? ACCESS_TOKEN_TTL_SECONDS),
    nonce: input.nonce
  });
}

function normalizeRequestedScope(
  requestedScope: string | null | undefined,
  client: OAuthClient,
  authEndpoint = false
):
  | { ok: true; value: string }
  | { ok: false; response: Response } {
  const requested = splitScope(requestedScope ?? "");
  const effectiveScopes = requested.length ? requested : client.scopes;
  if (!effectiveScopes.length) {
    return {
      ok: false,
      response: oauthError("invalid_scope", "OAuth 2.0 Parameter: scope", {
        errorUri: authEndpoint ? RFC6749_AUTH_ERROR_URI : RFC6749_TOKEN_ERROR_URI
      })
    };
  }
  const invalid = effectiveScopes.filter((scope) => !client.scopes.includes(scope));
  if (invalid.length) {
    return {
      ok: false,
      response: oauthError("invalid_scope", "OAuth 2.0 Parameter: scope", {
        errorUri: authEndpoint ? RFC6749_AUTH_ERROR_URI : RFC6749_TOKEN_ERROR_URI
      })
    };
  }

  return {
    ok: true,
    value: effectiveScopes.join(" ")
  };
}

function splitScope(scope: string): string[] {
  return scope
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function required(params: URLSearchParams, key: string): string | null {
  const value = params.get(key);
  return value && value.trim() ? value : null;
}

function optional(params: URLSearchParams, key: string): string | undefined {
  return params.get(key) ?? undefined;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function objectClaim(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function cleanCustomClaims(claims: TokenClaims): TokenClaims {
  const blocked = new Set(["iss", "aud", "exp", "iat", "jti", "nbf"]);
  return Object.fromEntries(Object.entries(claims).filter(([key]) => !blocked.has(key)));
}

function parseAuthorizationDetails(value: string | undefined): unknown {
  if (!value) return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function loadPasswordUsers(): Record<string, { password: string; claims: TokenClaims }> {
  if (!PASSWORD_GRANT_ENABLED || !PASSWORD_GRANT_USERS_JSON) return {};

  try {
    const parsed = JSON.parse(PASSWORD_GRANT_USERS_JSON) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const users: Record<string, { password: string; claims: TokenClaims }> = {};

    for (const [username, value] of Object.entries(parsed)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      const candidate = value as { password?: unknown; claims?: unknown };
      if (typeof candidate.password !== "string") continue;
      if (!candidate.claims || typeof candidate.claims !== "object" || Array.isArray(candidate.claims)) continue;
      users[username] = {
        password: candidate.password,
        claims: candidate.claims as TokenClaims
      };
    }

    return users;
  } catch {
    return {};
  }
}

function parseBasicAuth(header: string | null): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return {
      clientId: decoded.slice(0, separator),
      clientSecret: decoded.slice(separator + 1)
    };
  } catch {
    return null;
  }
}

async function bearerOrFormToken(request: NextRequest): Promise<string | null> {
  const authorization = request.headers.get("authorization");
  if (authorization?.toLowerCase().startsWith("bearer ")) {
    return authorization.slice("Bearer ".length).trim();
  }

  if (request.method === "POST") {
    const params = await readForm(request);
    return params.get("access_token") ?? params.get("token");
  }

  return request.nextUrl.searchParams.get("access_token");
}

function parseRequiredClaims(value: string | undefined): Array<{ path: string[]; value: string }> {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [path, ...rest] = entry.split(":");
      return {
        path: path.split("~"),
        value: rest.join(":")
      };
    })
    .filter((entry) => entry.path.length > 0 && entry.value.length > 0);
}

function claimsMatch(claims: TokenClaims, requiredClaims: Array<{ path: string[]; value: string }>): boolean {
  return requiredClaims.every((claim) => {
    let current: unknown = claims;
    for (const segment of claim.path) {
      if (!current || typeof current !== "object" || Array.isArray(current)) return false;
      current = (current as Record<string, unknown>)[segment];
    }
    return String(current) === claim.value;
  });
}

function addTokenDescriptor(
  response: Record<string, unknown[]>,
  clientId: string,
  descriptor: Record<string, unknown>
): void {
  if (!response[clientId]) response[clientId] = [];
  response[clientId].push(descriptor);
}
