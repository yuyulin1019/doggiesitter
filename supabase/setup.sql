-- Initial schema for the dog walking availability calendar.
-- Apply through the Supabase SQL editor or the Supabase migration API.

create table if not exists public.members (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null check (btrim(display_name) <> ''),
  role text not null check (role in ('owner', 'sitter')),
  created_at timestamptz not null default now()
);

create table if not exists public.availability (
  caregiver_id uuid not null references public.members (id) on delete cascade,
  available_on date not null,
  created_at timestamptz not null default now(),
  primary key (caregiver_id, available_on)
);

grant usage on schema public to authenticated;
revoke all on public.members, public.availability from anon;
grant select on public.members to authenticated;
grant update (display_name) on public.members to authenticated;
grant select, insert, delete on public.availability to authenticated;

alter table public.members enable row level security;
alter table public.availability enable row level security;

drop policy if exists "Signed-in users can view member directory" on public.members;
create policy "Signed-in users can view member directory"
  on public.members for select to authenticated using (true);

drop policy if exists "Members can update their own display name" on public.members;
create policy "Members can update their own display name"
  on public.members for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

drop policy if exists "Members can view shared availability" on public.availability;
create policy "Members can view shared availability"
  on public.availability for select to authenticated
  using (exists (
    select 1 from public.members m where m.id = (select auth.uid())
  ));

drop policy if exists "Sitters can add their own availability" on public.availability;
create policy "Sitters can add their own availability"
  on public.availability for insert to authenticated
  with check (exists (
    select 1 from public.members m
    where m.id = caregiver_id
      and m.id = (select auth.uid())
      and m.role = 'sitter'
  ));

drop policy if exists "Sitters can remove their own availability" on public.availability;
create policy "Sitters can remove their own availability"
  on public.availability for delete to authenticated
  using (exists (
    select 1 from public.members m
    where m.id = caregiver_id
      and m.id = (select auth.uid())
      and m.role = 'sitter'
  ));

-- These tables must be explicitly exposed to the Data API on newer Supabase projects.
grant select on public.members, public.availability to authenticated;

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'members'
  ) then
    alter publication supabase_realtime add table public.members;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'availability'
  ) then
    alter publication supabase_realtime add table public.availability;
  end if;
end
$$;
