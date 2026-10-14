begin;

create table if not exists public.device_approvals (
  user_id uuid not null references auth.users(id) on delete cascade,
  device_ref text not null check (device_ref ~ '^[0-9a-f]{64}$'),
  status text not null check (status in ('pending', 'approved', 'rejected', 'revoked', 'expired')),
  requested_at timestamptz not null default now(),
  approved_by text,
  approved_at timestamptz,
  approved_expires_at timestamptz,
  rejected_at timestamptz,
  revoked_at timestamptz,
  updated_by text not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, device_ref),
  check (
    (status in ('approved', 'expired') and approved_by is not null and approved_at is not null
      and approved_expires_at is not null)
    or (status not in ('approved', 'expired') and approved_by is null and approved_at is null
      and approved_expires_at is null)
  ),
  check ((status = 'revoked') = (revoked_at is not null)),
  check ((status = 'rejected') = (rejected_at is not null))
);

create table if not exists public.device_approval_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_ref text not null check (device_ref ~ '^[0-9a-f]{64}$'),
  previous_status text,
  new_status text not null check (new_status in ('pending', 'approved', 'rejected', 'revoked', 'expired')),
  actor text not null,
  occurred_at timestamptz not null default now()
);

create table if not exists public.device_approval_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists device_approval_events_user_device_time_idx
  on public.device_approval_events (user_id, device_ref, occurred_at desc);

create or replace function public.audit_device_approval_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  actor_value text;
begin
  actor_value := coalesce(
    nullif(new.updated_by, ''),
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    'server'
  );
  insert into public.device_approval_events (
    user_id, device_ref, previous_status, new_status, actor
  ) values (
    new.user_id,
    new.device_ref,
    case when tg_op = 'INSERT' then null else old.status end,
    new.status,
    actor_value
  );
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists device_approval_audit on public.device_approvals;
create trigger device_approval_audit
  before insert or update on public.device_approvals
  for each row execute function public.audit_device_approval_change();

create or replace function public.request_device_approval(
  p_user_id uuid,
  p_device_ref text,
  p_actor text
)
returns setof public.device_approvals
language sql
security definer
set search_path = public
as $$
  insert into public.device_approvals (
    user_id, device_ref, status, requested_at, approved_by, approved_at,
    approved_expires_at, rejected_at, revoked_at, updated_by
  ) values (
    p_user_id, p_device_ref, 'pending', now(), null, null, null, null, null, p_actor
  )
  on conflict (user_id, device_ref) do update
    set status = 'pending',
        requested_at = now(),
        approved_by = null,
        approved_at = null,
        approved_expires_at = null,
        rejected_at = null,
        revoked_at = null,
        updated_by = excluded.updated_by
    where public.device_approvals.status <> 'approved'
      or public.device_approvals.approved_expires_at <= now()
  returning *;
$$;

alter table public.device_approvals enable row level security;
alter table public.device_approval_events enable row level security;
alter table public.device_approval_admins enable row level security;

revoke all privileges on public.device_approvals from public, anon, authenticated;
revoke all privileges on public.device_approval_events from public, anon, authenticated;
revoke all privileges on public.device_approval_admins from public, anon, authenticated;
grant select, insert, update on public.device_approvals to service_role;
grant select on public.device_approval_events to service_role;
grant select on public.device_approval_admins to service_role;
revoke all privileges on function public.audit_device_approval_change() from public, anon, authenticated;
revoke all privileges on function public.request_device_approval(uuid, text, text) from public, anon, authenticated;
grant execute on function public.request_device_approval(uuid, text, text) to service_role;

commit;
