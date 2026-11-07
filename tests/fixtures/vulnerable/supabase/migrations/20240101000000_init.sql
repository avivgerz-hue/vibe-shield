create table public.accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id),
  balance numeric not null default 0,
  created_at timestamptz not null default now()
);

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

create policy "anything goes"
  on public.accounts
  for all
  using (true);

grant all on public.accounts to anon;
