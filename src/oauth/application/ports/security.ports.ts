import type { OAuthJwks } from "../../domain/value-objects/jwk";

export interface ClientAssertionReplayPort {
  remember(clientId: string, jti: string, expiresAt?: number): Promise<boolean>;
}

export interface ClientSecretVerifierPort {
  verify(secret: string, encodedHash: string): boolean;
}

export interface RemoteJwksPort {
  resolve(
    inlineJwks: OAuthJwks | undefined,
    jwksUri: string | undefined,
    metadata: Record<string, unknown>
  ): Promise<OAuthJwks | null>;
}
