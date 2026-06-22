-- QuickFade Authorization Code + PKCE configuration.
-- Run this in the Supabase SQL Editor after creating public.oauth_clients.
-- Replace the public key and environment-specific URLs before execution.

create table if not exists public.oauth_authentication_providers (
  provider_id text primary key,
  provider_name text not null,
  issuer text not null unique,
  login_url text not null
    check (login_url ~* '^https?://[^[:space:]]+$'),
  jwks jsonb,
  jwks_uri text,
  public_key text,
  user_jwt_max_ttl_seconds integer not null default 300
    check (user_jwt_max_ttl_seconds > 0),
  clock_skew_seconds integer not null default 60
    check (clock_skew_seconds between 0 and 300),
  provider_metadata jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (jwks is null or (jwks ? 'keys' and jsonb_typeof(jwks->'keys') = 'array')),
  check (
    ((jwks is not null)::integer +
     (jwks_uri is not null)::integer +
     (public_key is not null)::integer) = 1
  )
);

alter table public.oauth_authentication_providers
  add column if not exists login_url text;

create index if not exists oauth_authentication_providers_active_idx
  on public.oauth_authentication_providers (active);

create or replace function public.oauth_authentication_providers_touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists oauth_authentication_providers_touch_updated_at
  on public.oauth_authentication_providers;
create trigger oauth_authentication_providers_touch_updated_at
before update on public.oauth_authentication_providers
for each row
execute function public.oauth_authentication_providers_touch_updated_at();

alter table public.oauth_authentication_providers enable row level security;

grant select, insert, update on public.oauth_authentication_providers to service_role;
revoke all on public.oauth_authentication_providers from anon, authenticated;
revoke all on function public.oauth_authentication_providers_touch_updated_at()
  from anon, authenticated;

do $$
declare
  v_login_provider_public_key text := 'REPLACE_WITH_LOGIN_PROVIDER_PUBLIC_KEY_BASE64_DER';
  v_login_provider_login_url text := 'http://localhost:3002/api/v1/login';
  v_web_client_id text := 'REPLACE_WITH_WEB_CLIENT_ID';
  v_mobile_client_id text := 'REPLACE_WITH_MOBILE_CLIENT_ID';
  v_web_redirect_uri text := 'http://localhost:3002/api/v1/auth/callback';
  v_mobile_redirect_uri text := 'quickfade://auth/callback';
begin
  if v_login_provider_public_key like 'REPLACE_WITH_%' then
    raise exception 'Set v_login_provider_public_key before running this script';
  end if;

  if v_login_provider_login_url !~* '^https?://[^[:space:]]+$' then
    raise exception 'Set v_login_provider_login_url to a valid HTTP(S) URL';
  end if;

  if v_web_client_id like 'REPLACE_WITH_%' then
    raise exception 'Set v_web_client_id before running this script';
  end if;

  if v_mobile_client_id like 'REPLACE_WITH_%' then
    raise exception 'Set v_mobile_client_id before running this script';
  end if;

  if v_web_redirect_uri like 'REPLACE_WITH_%' then
    raise exception 'Set v_web_redirect_uri before running this script';
  end if;

  insert into public.oauth_authentication_providers (
    provider_id,
    provider_name,
    issuer,
    login_url,
    jwks,
    jwks_uri,
    public_key,
    user_jwt_max_ttl_seconds,
    clock_skew_seconds,
    provider_metadata,
    active
  ) values (
    'core-login-provider',
    'Core Login Provider',
    'core-login-provider',
    v_login_provider_login_url,
    null,
    null,
    v_login_provider_public_key,
    300,
    60,
    jsonb_build_object(
      'component_type', 'authentication_provider',
      'signing_algorithm', 'RS256'
    ),
    true
  )
  on conflict (provider_id) do update set
    provider_name = excluded.provider_name,
    issuer = excluded.issuer,
    login_url = excluded.login_url,
    jwks = excluded.jwks,
    jwks_uri = excluded.jwks_uri,
    public_key = excluded.public_key,
    user_jwt_max_ttl_seconds = excluded.user_jwt_max_ttl_seconds,
    clock_skew_seconds = excluded.clock_skew_seconds,
    provider_metadata = excluded.provider_metadata,
    active = excluded.active;

  -- Remove the legacy pseudo-client created by the previous version of this script.
  delete from public.oauth_clients
  where client_id = 'core-login-provider'
    and client_metadata->>'component_type' = 'authentication_provider';

  insert into public.oauth_clients (
    client_id,
    client_name,
    application_description,
    client_type,
    client_secret_hash,
    jwks,
    jwks_uri,
    public_key,
    redirect_uris,
    scopes,
    grant_types,
    auth_methods,
    require_pkce,
    require_consent,
    opaque_token,
    oauth_authentication_provider,
    backchannel_logout_uri,
    contact_email,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    session_ttl_seconds,
    client_metadata,
    active
  ) values
  (
    v_web_client_id,
    'QuickFade BFF Web',
    'Public web OAuth client using Authorization Code with PKCE',
    'public',
    null,
    null,
    null,
    null,
    array[v_web_redirect_uri],
    array['openid', 'profile', 'cl:core:profile:read', 'cl:quickfade:notes:read'],
    array['authorization_code', 'refresh_token'],
    array['none'],
    true,
    false,
    true,
    'core-login-provider',
    null,
    null,
    300,
    3600,
    43200,
    jsonb_build_object(
      'application_type', 'web',
      'token_format', 'opaque',
      'pkce_required', true
    ),
    true
  ),
  (
    v_mobile_client_id,
    'QuickFade BFF Mobile',
    'Public mobile OAuth client using Authorization Code with PKCE',
    'public',
    null,
    null,
    null,
    null,
    array[v_mobile_redirect_uri],
    array['openid', 'profile', 'cl:core:profile:read', 'cl:quickfade:notes:read'],
    array['authorization_code', 'refresh_token'],
    array['none'],
    true,
    false,
    true,
    'core-login-provider',
    null,
    null,
    300,
    3600,
    43200,
    jsonb_build_object(
      'application_type', 'mobile',
      'token_format', 'opaque',
      'pkce_required', true
    ),
    true
  )
  on conflict (client_id) do update set
    client_name = excluded.client_name,
    application_description = excluded.application_description,
    client_type = excluded.client_type,
    client_secret_hash = excluded.client_secret_hash,
    jwks = excluded.jwks,
    jwks_uri = excluded.jwks_uri,
    public_key = excluded.public_key,
    redirect_uris = excluded.redirect_uris,
    scopes = excluded.scopes,
    grant_types = excluded.grant_types,
    auth_methods = excluded.auth_methods,
    require_pkce = excluded.require_pkce,
    require_consent = excluded.require_consent,
    opaque_token = excluded.opaque_token,
    oauth_authentication_provider = excluded.oauth_authentication_provider,
    backchannel_logout_uri = excluded.backchannel_logout_uri,
    contact_email = excluded.contact_email,
    access_token_ttl_seconds = excluded.access_token_ttl_seconds,
    refresh_token_ttl_seconds = excluded.refresh_token_ttl_seconds,
    session_ttl_seconds = excluded.session_ttl_seconds,
    client_metadata = excluded.client_metadata,
    active = excluded.active;
end
$$;

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

do $$
begin
  if exists (
    select 1
    from public.oauth_clients client
    where client.oauth_authentication_provider is not null
      and not exists (
        select 1
        from public.oauth_authentication_providers provider
        where provider.provider_id = client.oauth_authentication_provider
      )
  ) then
    raise exception 'oauth_clients contains unknown oauth_authentication_provider values';
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'oauth_clients_authentication_provider_fk'
  ) then
    alter table public.oauth_clients
      add constraint oauth_clients_authentication_provider_fk
      foreign key (oauth_authentication_provider)
      references public.oauth_authentication_providers(provider_id)
      on update cascade
      on delete restrict;
  end if;
end
$$;

select
  provider_id,
  issuer,
  login_url,
  user_jwt_max_ttl_seconds,
  clock_skew_seconds,
  active
from public.oauth_authentication_providers
where provider_id = 'core-login-provider';

select
  client_id,
  client_type,
  redirect_uris,
  scopes,
  grant_types,
  auth_methods,
  require_pkce,
  opaque_token,
  oauth_authentication_provider,
  active
from public.oauth_clients
where oauth_authentication_provider = 'core-login-provider'
  and client_metadata->>'application_type' in ('web', 'mobile')
order by client_id;
