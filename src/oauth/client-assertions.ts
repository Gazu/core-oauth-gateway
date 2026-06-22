import { supabaseHeaders, supabaseRestUrl } from "./infrastructure/supabase";
import { nowSeconds } from "./jwt";
import { clientAuthLogger } from "./logger";

export async function rememberClientAssertionJti(
  clientId: string,
  jti: string,
  exp: unknown
): Promise<boolean> {
  const expiresAt = typeof exp === "number" ? exp : nowSeconds() + 300;
  return rememberClientAssertionJtiInSupabase(clientId, jti, expiresAt);
}

async function rememberClientAssertionJtiInSupabase(
  clientId: string,
  jti: string,
  expiresAt: number
): Promise<boolean> {
  const response = await fetch(supabaseRestUrl("oauth_client_assertion_jtis"), {
    method: "POST",
    headers: {
      ...supabaseHeaders(),
      Prefer: "return=minimal"
    },
    body: JSON.stringify({
      client_id: clientId,
      jti,
      expires_at: expiresAt
    })
  });

  if (response.status === 409) {
    clientAuthLogger.warn("Client assertion replay detected", {
      clientId,
      jti,
      backend: "supabase",
      tags: ["oauth", "client-auth"]
    });
    return false;
  }
  if (!response.ok) {
    throw new Error(`Supabase client assertion replay check failed: ${response.status} ${await response.text()}`);
  }
  clientAuthLogger.info("Client assertion jti recorded", {
    clientId,
    jti,
    expiresAt,
    backend: "supabase",
    tags: ["oauth", "client-auth"]
  });
  return true;
}
