import type {
  StoredAccessToken,
  StoredRefreshToken
} from "../../domain/entities/oauth-token";

export interface TokenRepositoryPort {
  cleanup(now?: number): Promise<void>;
  findAccessToken(token: string): Promise<StoredAccessToken | undefined>;
  findRefreshToken(token: string): Promise<StoredRefreshToken | undefined>;
  listTokens(): Promise<{
    accessTokens: StoredAccessToken[];
    refreshTokens: StoredRefreshToken[];
  }>;
  saveTokens(
    accessToken: StoredAccessToken,
    refreshToken?: StoredRefreshToken
  ): Promise<void>;
  revokeToken(token: string): Promise<boolean>;
  revokeTokenById(tokenId: string): Promise<boolean>;
  revokeTokensBySubject(subject?: string, clientIds?: string[]): Promise<number>;
}
