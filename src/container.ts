import type { OAuthApplicationPorts } from "@/oauth/application/ports/oauth-application.ports";
import {
  AuthorizeUseCase,
  CompleteUserAuthorizationUseCase,
  GetAuthDetailsUseCase,
  GetConsentUseCase,
  HandleUserErrorUseCase,
  PushedAuthorizeUseCase
} from "@/oauth/application/use-cases/authorization-use-cases";
import {
  GetDiscoveryDocumentUseCase,
  GetSigningCertificatesUseCase
} from "@/oauth/application/use-cases/discovery-use-cases";
import { HealthCheckUseCase } from "@/oauth/application/use-cases/health-check-use-case";
import { GetServiceInfoUseCase } from "@/oauth/application/use-cases/get-service-info-use-case";
import { IssueTokenUseCase } from "@/oauth/application/use-cases/issue-token-use-case";
import {
  GetTokenInfoUseCase,
  GetUserInfoUseCase,
  IntrospectTokenUseCase
} from "@/oauth/application/use-cases/token-query-use-cases";
import {
  ListAccessTokensUseCase,
  RevokeTokenByIdUseCase,
  RevokeTokenUseCase,
  RevokeTokensBySubjectUseCase
} from "@/oauth/application/use-cases/token-revocation-use-cases";
import { OAuthAuditAdapter } from "@/oauth/infrastructure/audit/oauth-audit.adapter";
import { loadOAuthApplicationConfig } from "@/oauth/infrastructure/config/oauth-application.config";
import { SupabaseHealthAdapter } from "@/oauth/infrastructure/health/supabase-health.adapter";
import { OAuthMaintenanceAdapter } from "@/oauth/infrastructure/maintenance/oauth-maintenance.adapter";
import { SupabaseOAuthStateRepository } from "@/oauth/infrastructure/persistence/supabase/oauth-state.repository";
import { SupabaseOAuthTokenRepository } from "@/oauth/infrastructure/persistence/supabase/oauth-token.repository";
import {
  ClientSecretVerifierAdapter,
  RemoteJwksAdapter,
  SupabaseClientAssertionReplayAdapter
} from "@/oauth/infrastructure/security/client-security.adapters";
import { OAuthJwtAdapter } from "@/oauth/infrastructure/security/oauth-jwt.adapter";
import { clientAuthLogger, oauthLogger, tokenLogger } from "@/oauth/logger";

export function createContainer(overrides: Partial<OAuthApplicationPorts> = {}) {
  const state = overrides.state ?? new SupabaseOAuthStateRepository();
  const tokens = overrides.tokens ?? new SupabaseOAuthTokenRepository();
  const ports: OAuthApplicationPorts = {
    state,
    tokens,
    jwt: overrides.jwt ?? new OAuthJwtAdapter(),
    audit: overrides.audit ?? new OAuthAuditAdapter(),
    replay: overrides.replay ?? new SupabaseClientAssertionReplayAdapter(),
    clientSecrets: overrides.clientSecrets ?? new ClientSecretVerifierAdapter(),
    remoteJwks: overrides.remoteJwks ?? new RemoteJwksAdapter(),
    health: overrides.health ?? new SupabaseHealthAdapter(),
    loggers: overrides.loggers ?? {
      oauth: oauthLogger,
      token: tokenLogger,
      clientAuth: clientAuthLogger
    },
    config: overrides.config ?? loadOAuthApplicationConfig(),
    maintenance: overrides.maintenance ?? new OAuthMaintenanceAdapter(state, tokens)
  };

  const serviceInfo = {
    service_name: process.env.SERVICE_NAME ?? "core-oauth-gateway",
    service_version: process.env.SERVICE_VERSION ?? "0.0.0",
    environment: process.env.ENVIRONMENT ?? process.env.NODE_ENV ?? "development"
  };

  return {
    ports,
    authorize: new AuthorizeUseCase(ports),
    pushedAuthorize: new PushedAuthorizeUseCase(ports),
    getConsent: new GetConsentUseCase(ports),
    getAuthDetails: new GetAuthDetailsUseCase(ports),
    completeUserAuthorization: new CompleteUserAuthorizationUseCase(ports),
    handleUserError: new HandleUserErrorUseCase(ports),
    issueToken: new IssueTokenUseCase(ports),
    getTokenInfo: new GetTokenInfoUseCase(ports),
    introspectToken: new IntrospectTokenUseCase(ports),
    getUserInfo: new GetUserInfoUseCase(ports),
    revokeToken: new RevokeTokenUseCase(ports),
    listAccessTokens: new ListAccessTokensUseCase(ports),
    revokeTokenById: new RevokeTokenByIdUseCase(ports),
    revokeTokensBySubject: new RevokeTokensBySubjectUseCase(ports),
    getDiscoveryDocument: new GetDiscoveryDocumentUseCase(ports),
    getSigningCertificates: new GetSigningCertificatesUseCase(ports),
    healthCheck: new HealthCheckUseCase(ports),
    getServiceInfo: new GetServiceInfoUseCase(serviceInfo)
  };
}

export type ApplicationContainer = ReturnType<typeof createContainer>;

type ContainerGlobal = typeof globalThis & {
  __coreOauthGatewayContainer?: ApplicationContainer;
};

export function getContainer(): ApplicationContainer {
  const globalState = globalThis as ContainerGlobal;
  globalState.__coreOauthGatewayContainer ??= createContainer();
  return globalState.__coreOauthGatewayContainer;
}
