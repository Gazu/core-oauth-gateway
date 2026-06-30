import type {
  ClientAssertionReplayPort,
  ClientSecretVerifierPort,
  RemoteJwksPort
} from "@/oauth/application/ports/security.ports";
import { rememberClientAssertionJti } from "@/oauth/client-assertions";
import { verifyClientSecret } from "@/oauth/client-secrets";
import type { OAuthJwks } from "@/oauth/domain/value-objects/jwk";
import { clientAuthLogger } from "@/oauth/logger";

export class SupabaseClientAssertionReplayAdapter implements ClientAssertionReplayPort {
  remember(clientId: string, jti: string, expiresAt?: number): Promise<boolean> {
    return rememberClientAssertionJti(clientId, jti, expiresAt);
  }
}

export class ClientSecretVerifierAdapter implements ClientSecretVerifierPort {
  verify(secret: string, encodedHash: string): boolean {
    return verifyClientSecret(secret, encodedHash);
  }
}

export class RemoteJwksAdapter implements RemoteJwksPort {
  async resolve(
    inlineJwks: OAuthJwks | undefined,
    jwksUri: string | undefined,
    metadata: Record<string, unknown>
  ): Promise<OAuthJwks | null> {
    if (inlineJwks?.keys?.length) return inlineJwks;
    if (!jwksUri) return null;

    try {
      const response = await fetch(jwksUri, {
        headers: { Accept: "application/json" },
        cache: "no-store"
      });
      if (!response.ok) {
        clientAuthLogger.error("JWKS request failed", {
          ...metadata,
          status: response.status,
          jwksUri,
          tags: ["oauth", "jwks"]
        });
        return null;
      }
      const jwks = (await response.json()) as OAuthJwks;
      if (!Array.isArray(jwks.keys)) {
        clientAuthLogger.error("JWKS response is invalid", {
          ...metadata,
          jwksUri,
          tags: ["oauth", "jwks"]
        });
        return null;
      }
      return jwks;
    } catch (error) {
      const message = error instanceof Error ? error.message : "JWKS request failed";
      clientAuthLogger.error(message, {
        ...metadata,
        jwksUri,
        tags: ["oauth", "jwks"],
        exception: error
      });
      return null;
    }
  }
}
