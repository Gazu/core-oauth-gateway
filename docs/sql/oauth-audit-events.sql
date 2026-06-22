-- Apply this script before deploying the audit-enabled gateway release.
-- It adds durable OAuth-flow correlation to tokens and an append-only audit log.

alter table public.oauth_tokens
  add column if not exists oauth_flow_id uuid;

update public.oauth_tokens
set oauth_flow_id = gen_random_uuid()
where oauth_flow_id is null;

alter table public.oauth_tokens
  alter column oauth_flow_id set not null;

create index if not exists oauth_tokens_oauth_flow_id_idx
  on public.oauth_tokens (oauth_flow_id);

create table if not exists public.oauth_audit_events (
  audit_id uuid primary key,
  audit_type text not null check (audit_type in (
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
  audit_status text not null check (audit_status in ('SUCCESS', 'FAILURE')),
  request_id text not null,
  trace_id text not null,
  span_id text not null,
  oauth_flow_id uuid not null,
  event_timestamp timestamptz not null,
  event_payload jsonb not null,
  created_at timestamptz not null default now()
);

alter table public.oauth_audit_events
  drop constraint if exists oauth_audit_events_audit_type_check;

alter table public.oauth_audit_events
  add constraint oauth_audit_events_audit_type_check
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
  ));

create index if not exists oauth_audit_events_flow_time_idx
  on public.oauth_audit_events (oauth_flow_id, event_timestamp);

create index if not exists oauth_audit_events_type_time_idx
  on public.oauth_audit_events (audit_type, event_timestamp);

create index if not exists oauth_audit_events_request_id_idx
  on public.oauth_audit_events (request_id);

alter table public.oauth_audit_events enable row level security;
alter table public.oauth_audit_events force row level security;

revoke all on table public.oauth_audit_events from public, anon, authenticated;
revoke all on table public.oauth_audit_events from service_role;
grant select, insert on table public.oauth_audit_events to service_role;

comment on table public.oauth_audit_events is
  'Append-only functional OAuth audit events. Tokens and credentials are never stored in clear text.';
