create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text
);

alter table public.profiles enable row level security;

create policy "profiles are owner readable"
  on public.profiles
  for select
  to authenticated
  using (auth.uid() = id);

create policy "profiles are owner writable"
  on public.profiles
  for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

grant select, insert, update on public.profiles to authenticated;
