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
grant select, insert, update, delete on table public.notes to service_role;

do $policies$
begin
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_select_own') then
    create policy notes_select_own on public.notes for select to authenticated
      using (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_insert_own') then
    create policy notes_insert_own on public.notes for insert to authenticated
      with check (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_update_own') then
    create policy notes_update_own on public.notes for update to authenticated
      using (owner_id = (select auth.uid()))
      with check (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_delete_own') then
    create policy notes_delete_own on public.notes for delete to authenticated
      using (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_select_owner_guard') then
    create policy notes_select_owner_guard on public.notes as restrictive for select to authenticated
      using (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_insert_owner_guard') then
    create policy notes_insert_owner_guard on public.notes as restrictive for insert to authenticated
      with check (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_update_owner_guard') then
    create policy notes_update_owner_guard on public.notes as restrictive for update to authenticated
      using (owner_id = (select auth.uid()))
      with check (owner_id = (select auth.uid()));
  end if;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'notes' and policyname = 'notes_delete_owner_guard') then
    create policy notes_delete_owner_guard on public.notes as restrictive for delete to authenticated
      using (owner_id = (select auth.uid()));
  end if;
end
$policies$;

commit;