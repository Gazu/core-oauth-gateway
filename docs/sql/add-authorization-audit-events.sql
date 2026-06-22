-- Extends oauth_audit_events with /oauth2/v1/authorize lifecycle events.

begin;

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

commit;

select conname, pg_get_constraintdef(oid) as definition
from pg_constraint
where conrelid = 'public.oauth_audit_events'::regclass
  and conname = 'oauth_audit_events_audit_type_check';
