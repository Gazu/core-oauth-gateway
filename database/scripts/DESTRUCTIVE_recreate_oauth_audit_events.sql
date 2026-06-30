-- WARNING: This script permanently deletes every OAuth audit event.
-- Use only when losing the current audit history is explicitly acceptable.
-- The transaction aborts if unknown objects depend on oauth_audit_events.

begin;

drop view if exists public.oauth_audit_events_ordered;
drop table if exists public.oauth_audit_events;

create table public.oauth_audit_events (
  audit_id uuid primary key,
  audit_type text not null,
  audit_status text not null,
  reason_code text,
  root_cause_code text,
  request_id text not null,
  trace_id text not null,
  span_id text not null,
  oauth_flow_id uuid not null,
  event_timestamp timestamptz not null,
  created_at timestamptz not null default now(),
  event_payload jsonb not null,
  constraint oauth_audit_events_audit_type_check
    check (audit_type in (
      'authorization_requested',
      'authorization_failed',
      'user_authenticated',
      'authentication_failed',
      'authorization_code_issued',
      'tokens_issued',
      'refresh_token_used',
      'token_revoked',
      'client_authenticated',
      'client_authentication_failed'
    )),
  constraint oauth_audit_events_audit_status_check
    check (audit_status in ('SUCCESS', 'FAILURE')),
  constraint oauth_audit_events_reason_code_check
    check (
      reason_code is null
      or (
        audit_status = 'FAILURE'
        and length(btrim(reason_code)) > 0
      )
    ),
  constraint oauth_audit_events_root_cause_code_check
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
    )
);

create index oauth_audit_events_flow_time_idx
  on public.oauth_audit_events (oauth_flow_id, event_timestamp);

create index oauth_audit_events_type_time_idx
  on public.oauth_audit_events (audit_type, event_timestamp);

create index oauth_audit_events_request_id_idx
  on public.oauth_audit_events (request_id);

create index oauth_audit_events_failure_classification_idx
  on public.oauth_audit_events (
    audit_type,
    reason_code,
    root_cause_code,
    event_timestamp desc
  )
  where audit_status = 'FAILURE';

alter table public.oauth_audit_events enable row level security;
alter table public.oauth_audit_events force row level security;

revoke all on table public.oauth_audit_events
  from public, anon, authenticated, service_role;
grant select, insert on table public.oauth_audit_events
  to service_role;

comment on table public.oauth_audit_events is
  'Append-only functional OAuth audit events. Tokens and credentials are never stored in clear text.';
comment on column public.oauth_audit_events.reason_code is
  'Stable functional failure category. Null for successful audit events.';
comment on column public.oauth_audit_events.root_cause_code is
  'Detailed internal failure cause. Never returned in public OAuth responses.';

commit;
