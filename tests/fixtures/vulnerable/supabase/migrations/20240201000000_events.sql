create table public.events (
  id bigserial primary key,
  payload jsonb
);

alter table public.events enable row level security;

create policy "events readable by authenticated"
  on public.events
  for select
  to authenticated;
