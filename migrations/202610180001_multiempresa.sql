create extension if not exists pgcrypto;

create table if not exists public.businesses (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 160),
  representative text not null default '',
  phone text not null default '',
  contact_email text not null default '',
  opening_days integer not null default 26 check (opening_days between 1 and 31),
  status text not null default 'active' check (status in ('active', 'blocked')),
  created_at timestamptz not null default now()
);

alter table public.businesses add column if not exists representative text not null default '';
alter table public.businesses add column if not exists phone text not null default '';
alter table public.businesses add column if not exists contact_email text not null default '';
alter table public.businesses add column if not exists opening_days integer not null default 26;

create table if not exists public.business_memberships (
  business_id uuid not null references public.businesses(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner', 'member')),
  created_at timestamptz not null default now(),
  primary key (business_id, user_id)
);

create index if not exists business_memberships_user_id_idx
  on public.business_memberships(user_id);

create table if not exists public.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.business_app_state (
  business_id uuid primary key references public.businesses(id) on delete cascade,
  state jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.businesses enable row level security;
alter table public.business_memberships enable row level security;
alter table public.platform_admins enable row level security;
alter table public.business_app_state enable row level security;

drop policy if exists "Members can read their active businesses" on public.businesses;
create policy "Members can read their active businesses"
  on public.businesses for select to authenticated
  using (
    status = 'active'
    and exists (
      select 1 from public.business_memberships membership
      where membership.business_id = businesses.id
        and membership.user_id = (select auth.uid())
    )
  );

drop policy if exists "Users can read their own memberships" on public.business_memberships;
create policy "Users can read their own memberships"
  on public.business_memberships for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "Members can read active business state" on public.business_app_state;
create policy "Members can read active business state"
  on public.business_app_state for select to authenticated
  using (
    exists (
      select 1 from public.business_memberships membership
      join public.businesses business on business.id = membership.business_id
      where membership.business_id = business_app_state.business_id
        and membership.user_id = (select auth.uid())
        and business.status = 'active'
    )
  );

drop policy if exists "Members can insert active business state" on public.business_app_state;
create policy "Members can insert active business state"
  on public.business_app_state for insert to authenticated
  with check (
    exists (
      select 1 from public.business_memberships membership
      join public.businesses business on business.id = membership.business_id
      where membership.business_id = business_app_state.business_id
        and membership.user_id = (select auth.uid())
        and business.status = 'active'
    )
  );

drop policy if exists "Members can update active business state" on public.business_app_state;
create policy "Members can update active business state"
  on public.business_app_state for update to authenticated
  using (
    exists (
      select 1 from public.business_memberships membership
      join public.businesses business on business.id = membership.business_id
      where membership.business_id = business_app_state.business_id
        and membership.user_id = (select auth.uid())
        and business.status = 'active'
    )
  )
  with check (
    exists (
      select 1 from public.business_memberships membership
      join public.businesses business on business.id = membership.business_id
      where membership.business_id = business_app_state.business_id
        and membership.user_id = (select auth.uid())
        and business.status = 'active'
    )
  );

revoke all on public.platform_admins from anon, authenticated;
revoke all on public.businesses, public.business_memberships, public.business_app_state from anon, authenticated;
grant select on public.businesses, public.business_memberships, public.business_app_state to authenticated;
grant insert, update on public.business_app_state to authenticated;
