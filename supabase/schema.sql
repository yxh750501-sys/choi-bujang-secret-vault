begin;

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

revoke all privileges on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;
grant select, insert, update, delete on table public.notes to service_role;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;
drop policy if exists notes_select_owner_guard on public.notes;
drop policy if exists notes_insert_owner_guard on public.notes;
drop policy if exists notes_update_owner_guard on public.notes;
drop policy if exists notes_delete_owner_guard on public.notes;

create policy notes_select_own
  on public.notes
  for select
  to authenticated
  using (owner_id = (select auth.uid()));

create policy notes_insert_own
  on public.notes
  for insert
  to authenticated
  with check (owner_id = (select auth.uid()));

create policy notes_update_own
  on public.notes
  for update
  to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy notes_delete_own
  on public.notes
  for delete
  to authenticated
  using (owner_id = (select auth.uid()));

create policy notes_select_owner_guard
  on public.notes
  as restrictive
  for select
  to authenticated
  using (owner_id = (select auth.uid()));

create policy notes_insert_owner_guard
  on public.notes
  as restrictive
  for insert
  to authenticated
  with check (owner_id = (select auth.uid()));

create policy notes_update_owner_guard
  on public.notes
  as restrictive
  for update
  to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy notes_delete_owner_guard
  on public.notes
  as restrictive
  for delete
  to authenticated
  using (owner_id = (select auth.uid()));

commit;