export const AUDIT_ROOT_CAUSE_CODES = [
  "jwt_malformed",
  "jwt_header_missing",
  "signing_algorithm_not_allowed",
  "kid_missing",
  "kid_not_found",
  "jwt_payload_invalid",
  "expiration_missing",
  "assertion_expired",
  "issuer_missing",
  "issuer_subject_mismatch",
  "client_id_mismatch",
  "audience_missing",
  "audience_invalid",
  "jti_missing",
  "jti_already_registered",
  "client_record_not_found",
  "client_inactive",
  "authentication_method_not_allowed",
  "public_key_not_configured",
  "jwks_resolution_failed",
  "signature_invalid"
] as const;

export type AuditRootCauseCode = (typeof AUDIT_ROOT_CAUSE_CODES)[number];

const AUDIT_ROOT_CAUSE_CODE_SET = new Set<string>(AUDIT_ROOT_CAUSE_CODES);

export function isAuditRootCauseCode(value: unknown): value is AuditRootCauseCode {
  return typeof value === "string" && AUDIT_ROOT_CAUSE_CODE_SET.has(value);
}
