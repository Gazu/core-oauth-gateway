import type {
  ClientAssertionValidationResult,
  InvalidAssertion
} from "../models/assertion-validation-result";
import type { OAuthApplicationPorts } from "../ports/oauth-application.ports";
import type { OAuthClient } from "../../domain/entities/oauth-client";
import type { JwtPayload } from "../../domain/value-objects/token-claims";

export type ClientAssertionValidationOptions = {
  assertion: string;
  acceptedAudiences: readonly string[];
  expectedClientId?: string;
  requireClientSubject?: boolean;
  consumeReplay?: boolean;
};

export class ClientAssertionValidationService {
  constructor(private readonly ports: OAuthApplicationPorts) {}

  async validate<TPayload extends JwtPayload = JwtPayload>(
    options: ClientAssertionValidationOptions
  ): Promise<ClientAssertionValidationResult<TPayload>> {
    const { assertion } = options;
    const compactParts = assertion.split(".");
    if (compactParts.length !== 3 || compactParts.some((part) => part.length === 0)) {
      return invalidAssertion("jwt_malformed");
    }

    const header = this.ports.jwt.decodeHeader(assertion);
    if (!header) return invalidAssertion("jwt_header_missing");
    if (header.alg !== "RS256") {
      return invalidAssertion("signing_algorithm_not_allowed");
    }
    if (typeof header.kid !== "string" || header.kid.length === 0) {
      return invalidAssertion("kid_missing");
    }

    const payload = this.ports.jwt.decode<TPayload>(assertion);
    if (!payload) return invalidAssertion("jwt_payload_invalid");
    if (payload.exp === undefined) {
      return invalidAssertion("expiration_missing", claimClientId(payload));
    }
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
      return invalidAssertion("jwt_payload_invalid", claimClientId(payload));
    }
    if (this.ports.jwt.isExpired(payload)) {
      return invalidAssertion("assertion_expired", claimClientId(payload));
    }

    const clientId = claimClientId(payload);
    if (!clientId) return invalidAssertion("issuer_missing");

    const audiences = this.ports.jwt.normalizeAudience(payload.aud);
    if (audiences.length === 0) {
      return invalidAssertion("audience_missing", clientId);
    }
    if (!audiences.some((audience) => options.acceptedAudiences.includes(audience))) {
      return invalidAssertion("audience_invalid", clientId);
    }

    if (typeof payload.jti !== "string" || payload.jti.length === 0) {
      return invalidAssertion("jti_missing", clientId);
    }

    const clientLookup = this.ports.state.lookupClient(clientId);
    if (clientLookup.status === "not_found") {
      return invalidAssertion("client_record_not_found", clientId);
    }
    if (clientLookup.status === "inactive") {
      return invalidAssertion("client_inactive", clientId);
    }

    const { client } = clientLookup;
    if (!client.authMethods.includes("private_key_jwt")) {
      return invalidAssertion("authentication_method_not_allowed", clientId);
    }
    if (options.expectedClientId && options.expectedClientId !== client.clientId) {
      return invalidAssertion("client_id_mismatch", clientId);
    }
    if (
      options.requireClientSubject &&
      (payload.iss !== client.clientId || payload.sub !== client.clientId)
    ) {
      return invalidAssertion("issuer_subject_mismatch", clientId);
    }

    if (!client.jwks?.keys?.length && !client.jwksUri) {
      return invalidAssertion("public_key_not_configured", clientId);
    }
    const clientJwks = await this.ports.remoteJwks.resolve(
      client.jwks,
      client.jwksUri,
      { clientId }
    );
    if (!clientJwks) {
      return invalidAssertion("jwks_resolution_failed", clientId);
    }
    if (!clientJwks.keys.some((key) => key.kid === header.kid)) {
      return invalidAssertion("kid_not_found", clientId);
    }
    if (!this.ports.jwt.verifySignature(assertion, clientJwks)) {
      return invalidAssertion("signature_invalid", clientId);
    }
    if (options.consumeReplay !== false) {
      const replayFailure = await this.rememberReplay(client, payload);
      if (replayFailure) return replayFailure;
    }

    return { valid: true, header, payload, client };
  }

  async rememberReplay(
    client: OAuthClient,
    payload: JwtPayload
  ): Promise<InvalidAssertion | null> {
    const clientId = client.clientId;
    if (typeof payload.jti !== "string" || payload.jti.length === 0) {
      return invalidAssertion("jti_missing", clientId);
    }
    if (!(await this.ports.replay.remember(clientId, payload.jti, payload.exp))) {
      return invalidAssertion("jti_already_registered", clientId);
    }
    return null;
  }
}

function claimClientId(payload: JwtPayload): string | undefined {
  return typeof payload.iss === "string" && payload.iss.length > 0
    ? payload.iss
    : undefined;
}

function invalidAssertion(
  rootCauseCode: InvalidAssertion["rootCauseCode"],
  clientId?: string
): InvalidAssertion {
  const reasonCode: InvalidAssertion["reasonCode"] =
    rootCauseCode === "client_record_not_found"
      ? "unknown_client"
      : rootCauseCode === "client_id_mismatch"
        ? "client_id_mismatch"
        : rootCauseCode === "jti_already_registered"
          ? "client_assertion_replay"
          : "invalid_client_assertion";

  return { valid: false, reasonCode, rootCauseCode, clientId };
}
