select
  c.relrowsecurity as rls_enabled,
  has_table_privilege('anon', 'public.notes', 'select') as anon_can_select,
  has_table_privilege('authenticated', 'public.notes', 'select') as authenticated_can_select,
  has_table_privilege('service_role', 'public.notes', 'select') as service_role_can_select
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relname = 'notes';

select count(*) as policy_count
from pg_policies
where schemaname = 'public' and tablename = 'notes';