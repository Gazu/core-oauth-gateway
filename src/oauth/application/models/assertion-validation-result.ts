import type { AuditRootCauseCode } from "../../domain/value-objects/audit-root-cause";
import type { OAuthClient } from "../../domain/entities/oauth-client";
import type {
  JwtHeader,
  JwtPayload
} from "../../domain/value-objects/token-claims";

export type AssertionValidationReasonCode =
  | "invalid_client_assertion"
  | "client_assertion_replay"
  | "client_id_mismatch"
  | "unknown_client";

export type ValidAssertion<TPayload extends JwtPayload = JwtPayload> = {
  valid: true;
  header: JwtHeader;
  payload: TPayload;
};

export type InvalidAssertion = {
  valid: false;
  reasonCode: AssertionValidationReasonCode;
  rootCauseCode: AuditRootCauseCode;
  clientId?: string;
};

export type AssertionValidationResult<TPayload extends JwtPayload = JwtPayload> =
  | ValidAssertion<TPayload>
  | InvalidAssertion;

export type ClientAssertionValidationResult<
  TPayload extends JwtPayload = JwtPayload
> =
  | (ValidAssertion<TPayload> & { client: OAuthClient })
  | InvalidAssertion;
