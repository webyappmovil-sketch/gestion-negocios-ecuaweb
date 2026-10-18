-- Run once after creating the initial user in Supabase Authentication.
-- Replace both values before executing.
do $$
declare
  admin_id uuid;
  initial_business_id uuid;
begin
  select id into admin_id
  from auth.users
  where lower(email) = lower('webyappmovil@gmail.com')
  limit 1;

  if admin_id is null then
    raise exception 'Create the administrator account in Supabase Auth before running this bootstrap.';
  end if;

  insert into public.platform_admins(user_id)
  values (admin_id)
  on conflict (user_id) do nothing;

  insert into public.businesses(name)
  values ('APP FINANCIERA NEGOCIOS')
  returning id into initial_business_id;

  insert into public.business_memberships(business_id, user_id, role)
  values (initial_business_id, admin_id, 'owner')
  on conflict (business_id, user_id) do nothing;
end
$$;
