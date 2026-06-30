import { readFileSync } from "node:fs";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { AssertionValidationResult } from "../../src/oauth/application/models/assertion-validation-result";
import {
  AUDIT_ROOT_CAUSE_CODES,
  isAuditRootCauseCode
} from "../../src/oauth/domain/value-objects/audit-root-cause";

describe("assertion validation contracts", () => {
  it("exposes a closed root cause taxonomy with runtime validation", () => {
    expect(AUDIT_ROOT_CAUSE_CODES).toContain("assertion_expired");
    expect(AUDIT_ROOT_CAUSE_CODES).toContain("jti_already_registered");
    expect(AUDIT_ROOT_CAUSE_CODES).toContain("client_record_not_found");
    expect(isAuditRootCauseCode("signature_invalid")).toBe(true);
    expect(isAuditRootCauseCode("database_error")).toBe(false);
  });

  it("narrows successful and failed assertion validation results", () => {
    const success: AssertionValidationResult = {
      valid: true,
      header: { alg: "RS256", kid: "signing-key" },
      payload: { iss: "client-id", exp: 1_800_000_000 }
    };
    const failure: AssertionValidationResult = {
      valid: false,
      reasonCode: "invalid_client_assertion",
      rootCauseCode: "assertion_expired"
    };

    if (success.valid) {
      expectTypeOf(success.payload.iss).toEqualTypeOf<string | undefined>();
      expect(success.header.kid).toBe("signing-key");
    }
    if (!failure.valid) {
      expectTypeOf(failure.rootCauseCode).toMatchTypeOf<string>();
      expect(failure.rootCauseCode).toBe("assertion_expired");
    }
  });

  it("keeps the database constraint aligned with the root cause taxonomy", () => {
    const migration = readFileSync(
      new URL(
        "../../database/migrations/20260630_add_audit_failure_classification.sql",
        import.meta.url
      ),
      "utf8"
    );

    for (const rootCauseCode of AUDIT_ROOT_CAUSE_CODES) {
      expect(migration).toContain(`'${rootCauseCode}'`);
    }
    expect(migration).toContain("oauth_audit_events_reason_code_check");
    expect(migration).toContain("oauth_audit_events_root_cause_code_check");
    expect(migration).toContain("oauth_audit_events_failure_classification_idx");
    expect(migration).toContain("where audit_status = 'FAILURE'");
    expect(migration).toContain("drop view if exists public.oauth_audit_events_ordered");
    expect(migration).not.toContain("create view public.oauth_audit_events_ordered");
    expect(migration).not.toContain(
      "create or replace view public.oauth_audit_events_ordered"
    );
  });

  it("keeps the destructive audit reset script complete and explicit", () => {
    const resetScript = readFileSync(
      new URL(
        "../../database/scripts/DESTRUCTIVE_recreate_oauth_audit_events.sql",
        import.meta.url
      ),
      "utf8"
    );

    expect(resetScript).toContain("WARNING: This script permanently deletes");
    expect(resetScript).toContain("drop view if exists public.oauth_audit_events_ordered");
    expect(resetScript).toContain("drop table if exists public.oauth_audit_events;");
    expect(resetScript).not.toContain("drop table if exists public.oauth_audit_events cascade");
    expect(resetScript).not.toContain("create view public.oauth_audit_events_ordered");
    expect(resetScript).toContain(
      [
        "audit_status text not null,",
        "  reason_code text,",
        "  root_cause_code text,",
        "  request_id text not null,"
      ].join("\n")
    );
    expect(resetScript).toContain("enable row level security");
    expect(resetScript).toContain("force row level security");
    expect(resetScript).toContain(
      "grant select, insert on table public.oauth_audit_events"
    );
    for (const rootCauseCode of AUDIT_ROOT_CAUSE_CODES) {
      expect(resetScript).toContain(`'${rootCauseCode}'`);
    }
  });
});
