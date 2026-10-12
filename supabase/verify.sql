select
  role_name,
  has_table_privilege(role_name::name, 'public.notes', 'select') as can_select,
  has_table_privilege(role_name::name, 'public.notes', 'insert') as can_insert,
  has_table_privilege(role_name::name, 'public.notes', 'update') as can_update,
  has_table_privilege(role_name::name, 'public.notes', 'delete') as can_delete
from (values ('anon'), ('authenticated'), ('service_role')) as roles(role_name);

select grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

select count(*) as policy_count
from pg_policies
where schemaname = 'public' and tablename = 'notes';