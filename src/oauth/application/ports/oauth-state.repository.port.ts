import type {
  AuthorizationCode,
  AuthorizationRequest,
  PushedAuthorizationRequest
} from "../../domain/entities/authorization";
import type { OAuthAuthenticationProvider } from "../../domain/entities/oauth-authentication-provider";
import type {
  OAuthClient,
  OAuthClientLookupResult
} from "../../domain/entities/oauth-client";

export interface OAuthStateRepositoryPort {
  refresh(now?: number, force?: boolean): Promise<void>;
  cleanupTransient(now?: number): Promise<void>;
  getClient(clientId: string): OAuthClient | undefined;
  lookupClient(clientId: string): OAuthClientLookupResult;
  getAuthenticationProvider(providerId: string): OAuthAuthenticationProvider | undefined;
  getAuthorizationRequest(oauthKey: string): AuthorizationRequest | undefined;
  saveAuthorizationRequest(request: AuthorizationRequest): Promise<void>;
  deleteAuthorizationRequest(oauthKey: string): Promise<void>;
  getPushedRequest(requestUri: string): PushedAuthorizationRequest | undefined;
  savePushedRequest(request: PushedAuthorizationRequest): Promise<void>;
  getAuthorizationCode(code: string): AuthorizationCode | undefined;
  saveAuthorizationCode(code: AuthorizationCode): Promise<void>;
}
