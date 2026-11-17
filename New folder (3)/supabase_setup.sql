-- Run this ONCE in the Supabase SQL Editor (after supabase_setup.sql).
-- Adds: image messages, delete-own-message, real coin gifts between friends,
-- the chat-images storage bucket, and realtime for instant chat.

-- 1) Image messages
alter table public.messages add column if not exists image_url text;

do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
    where conrelid = 'public.messages'::regclass and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%body%'
  loop
    execute format('alter table public.messages drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.messages add constraint messages_body_check check (
  char_length(body) <= 500
  and (char_length(btrim(body)) > 0 or image_url is not null)
  and (image_url is null or image_url ~ '^https://')
);

drop policy if exists "Members can delete their messages" on public.messages;
create policy "Members can delete their messages"
  on public.messages for delete to authenticated
  using (auth.uid() = from_id);
grant delete on public.messages to authenticated;

-- 2) Image storage (public bucket, random file names, 5 MB limit)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('chat-images', 'chat-images', true, 5242880,
        array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update
  set public = true,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Members upload own chat images" on storage.objects;
create policy "Members upload own chat images"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'chat-images' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "Members delete own chat images" on storage.objects;
create policy "Members delete own chat images"
  on storage.objects for delete to authenticated
  using (bucket_id = 'chat-images' and (storage.foldername(name))[1] = auth.uid()::text);

-- 3) Gifts between real friends
create table if not exists public.gifts (
  id uuid primary key default gen_random_uuid(),
  from_id uuid not null references public.profiles(id) on delete cascade,
  to_id uuid not null references public.profiles(id) on delete cascade,
  amount integer not null check (amount between 1 and 100000),
  msg text not null default '' check (char_length(msg) <= 120),
  claimed boolean not null default false,
  created_at timestamptz not null default now(),
  check (from_id <> to_id)
);
create index if not exists gifts_to_id on public.gifts(to_id, created_at desc);
alter table public.gifts enable row level security;

drop policy if exists "Members can view their gifts" on public.gifts;
create policy "Members can view their gifts"
  on public.gifts for select to authenticated
  using (auth.uid() = from_id or auth.uid() = to_id);

drop policy if exists "Friends can send gifts" on public.gifts;
create policy "Friends can send gifts"
  on public.gifts for insert to authenticated
  with check (
    auth.uid() = from_id
    and claimed = false
    and exists (
      select 1 from public.friend_requests f
      where f.status = 'accepted'
        and ((f.from_id = auth.uid() and f.to_id = gifts.to_id)
          or (f.to_id = auth.uid() and f.from_id = gifts.to_id))
    )
  );

drop policy if exists "Recipients can claim gifts" on public.gifts;
create policy "Recipients can claim gifts"
  on public.gifts for update to authenticated
  using (auth.uid() = to_id and claimed = false)
  with check (auth.uid() = to_id and claimed = true);

grant select, insert on public.gifts to authenticated;
revoke update on public.gifts from authenticated;
grant update (claimed) on public.gifts to authenticated;

-- 4) Realtime (instant messages, gifts, friend requests)
do $$
declare t text;
begin
  foreach t in array array['messages','gifts','friend_requests'] loop
    if not exists (select 1 from pg_publication_tables
                   where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

notify pgrst, 'reload schema';

-- 5) Item gifts (a friend can only be gifted each item once)
alter table public.gifts add column if not exists item_id text;
alter table public.gifts add column if not exists item_title text;
create unique index if not exists gifts_one_item_per_friend
  on public.gifts (to_id, item_id) where item_id is not null;
notify pgrst, 'reload schema';

-- ==================================================================
-- 6) ADMIN + CC UNLOCKS + RESERVED NAMES
--    Before running this part: create the account with username  fishy  on the site.
-- ==================================================================
create table if not exists public.admins (user_id uuid primary key references auth.users(id) on delete cascade);
alter table public.admins enable row level security;   -- no policies: the website can't read or edit it

create or replace function public.is_admin() returns boolean
language sql security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;
grant execute on function public.is_admin() to authenticated;

insert into public.admins (user_id)
select id from auth.users where email = 'fishy@users.tikos-app.com'
on conflict do nothing;

-- admins can send coins / items to anyone (not only friends)
drop policy if exists "Admins can send gifts" on public.gifts;
create policy "Admins can send gifts"
  on public.gifts for insert to authenticated
  with check (public.is_admin() and auth.uid() = from_id and claimed = false);

-- locked CC (Tikos 4K Elite) unlocks
create table if not exists public.cc_unlocks (
  user_id uuid references auth.users(id) on delete cascade,
  cc text not null,
  primary key (user_id, cc)
);
alter table public.cc_unlocks enable row level security;
drop policy if exists "Read own unlocks" on public.cc_unlocks;
create policy "Read own unlocks" on public.cc_unlocks for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
drop policy if exists "Admins manage unlocks" on public.cc_unlocks;
create policy "Admins manage unlocks" on public.cc_unlocks for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
grant select, insert, update, delete on public.cc_unlocks to authenticated;

-- one person per username (any capitalisation)
do $$ begin
  create unique index if not exists profiles_username_ci on public.profiles (lower(username));
exception when others then
  raise notice 'Usernames not unique yet: two profiles share a name. Rename one and run this block again.';
end $$;

-- block look-alikes of "fishy" (f1shy, xfishyx ...) and staff names at sign-up
create or replace function public.tk_block_reserved() returns trigger
language plpgsql security definer set search_path = public as $$
declare raw text := lower(coalesce(new.raw_user_meta_data->>'username',''));
        n text;
begin
  n := regexp_replace(translate(raw, '01345$@!|7', 'oieassaiit'), '[^a-z]', '', 'g');
  if raw <> 'fishy' and n like '%fishy%' then raise exception 'That username is reserved'; end if;
  if n in ('admin','administrator','owner','staff','moderator','support','system','official','tikos','nate') then
    raise exception 'That username is reserved';
  end if;
  return new;
end $$;
drop trigger if exists tk_block_reserved on auth.users;
create trigger tk_block_reserved before insert on auth.users
  for each row execute function public.tk_block_reserved();

notify pgrst, 'reload schema';


-- ==================================================================
-- 7) SIGN-UP FIX ("Too many attempts" / "Email rate limit")
--    Accounts are username + password, so there is no real inbox to confirm.
--    In the Supabase dashboard: Authentication -> Sign In / Providers -> Email -> turn OFF "Confirm email".
--    Then run this to activate any accounts created while it was still on:
-- ==================================================================
update auth.users
   set email_confirmed_at = coalesce(email_confirmed_at, now())
 where email like '%@users.tikos-app.com' and email_confirmed_at is null;