-- Adds the login redirect URL to existing authentication-provider records.
-- For production, replace the local URL below with the deployed login-provider URL.

begin;

alter table public.oauth_authentication_providers
  add column if not exists login_url text;

update public.oauth_authentication_providers
set login_url = 'http://localhost:3002/api/v1/login'
where provider_id = 'core-login-provider';

do $$
begin
  if exists (
    select 1
    from public.oauth_authentication_providers
    where login_url is null
       or login_url !~* '^https?://[^[:space:]]+$'
  ) then
    raise exception
      'Every oauth_authentication_providers row must have a valid HTTP(S) login_url';
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'oauth_authentication_providers_login_url_check'
      and conrelid = 'public.oauth_authentication_providers'::regclass
  ) then
    alter table public.oauth_authentication_providers
      add constraint oauth_authentication_providers_login_url_check
      check (login_url ~* '^https?://[^[:space:]]+$');
  end if;
end
$$;

alter table public.oauth_authentication_providers
  alter column login_url set not null;

grant select on table public.oauth_authentication_providers to service_role;

commit;

select provider_id, issuer, login_url, active
from public.oauth_authentication_providers
order by provider_id;
