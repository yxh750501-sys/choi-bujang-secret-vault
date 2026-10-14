-- After applying the device approvals migration, replace the placeholder with
-- the UUID of an existing user from Supabase Dashboard > Authentication > Users.
-- Run manually in the Supabase SQL Editor as a database administrator.
insert into public.device_approval_admins (user_id, enabled)
values ('REPLACE_WITH_EXISTING_SUPABASE_AUTH_USER_UUID'::uuid, true)
on conflict (user_id) do update
  set enabled = excluded.enabled,
      updated_at = now();
