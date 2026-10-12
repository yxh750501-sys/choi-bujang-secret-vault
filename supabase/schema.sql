create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

revoke all privileges on table public.notes from public, anon, authenticated;
grant select on table public.notes to service_role;