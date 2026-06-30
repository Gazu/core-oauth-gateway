begin;

drop view if exists public.oauth_audit_events_ordered;

alter table public.oauth_audit_events
  add column if not exists reason_code text,
  add column if not exists root_cause_code text;

update public.oauth_audit_events
set
  reason_code = nullif(btrim(event_payload ->> 'reasonCode'), ''),
  root_cause_code = nullif(btrim(event_payload ->> 'rootCauseCode'), '')
where audit_status = 'FAILURE'
  and (
    reason_code is null
    or root_cause_code is null
  );

alter table public.oauth_audit_events
  drop constraint if exists oauth_audit_events_reason_code_check,
  drop constraint if exists oauth_audit_events_root_cause_code_check;

alter table public.oauth_audit_events
  add constraint oauth_audit_events_reason_code_check
  check (
    reason_code is null
    or (
      audit_status = 'FAILURE'
      and length(btrim(reason_code)) > 0
    )
  ),
  add constraint oauth_audit_events_root_cause_code_check
  check (
    root_cause_code is null
    or (
      audit_status = 'FAILURE'
      and reason_code is not null
      and root_cause_code in (
        'jwt_malformed',
        'jwt_header_missing',
        'signing_algorithm_not_allowed',
        'kid_missing',
        'kid_not_found',
        'jwt_payload_invalid',
        'expiration_missing',
        'assertion_expired',
        'issuer_missing',
        'issuer_subject_mismatch',
        'client_id_mismatch',
        'audience_missing',
        'audience_invalid',
        'jti_missing',
        'jti_already_registered',
        'client_record_not_found',
        'client_inactive',
        'authentication_method_not_allowed',
        'public_key_not_configured',
        'jwks_resolution_failed',
        'signature_invalid'
      )
    )
  );

create index if not exists oauth_audit_events_failure_classification_idx
  on public.oauth_audit_events (
    audit_type,
    reason_code,
    root_cause_code,
    event_timestamp desc
  )
  where audit_status = 'FAILURE';

comment on column public.oauth_audit_events.reason_code is
  'Stable functional failure category. Null for successful audit events.';

comment on column public.oauth_audit_events.root_cause_code is
  'Detailed internal failure cause. Never returned in public OAuth responses.';

commit;
