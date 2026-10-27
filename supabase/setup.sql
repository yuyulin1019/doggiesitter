-- Doggiesitter：每位保母一條專屬連結，登記「日期＋時段」。
-- 瀏覽器不能直接讀寫資料表；所有讀寫都經過下面的函式，函式先用連結 token
-- 找出「你是誰」，再只對你自己的資料動手。資料庫只存 token 的雜湊值。
begin;

create extension if not exists pgcrypto with schema extensions;
create extension if not exists btree_gist with schema extensions;

create table if not exists public.members (
  id uuid primary key default gen_random_uuid(),
  display_name text not null check (btrim(display_name) <> ''),
  role text not null default 'sitter' check (role in ('owner', 'sitter')),
  created_at timestamptz not null default now()
);
alter table public.members drop constraint if exists members_id_fkey;
alter table public.members alter column id set default gen_random_uuid();
alter table public.members alter column role set default 'sitter';
alter table public.members drop constraint if exists members_name_length;
alter table public.members add constraint members_name_length
  check (char_length(btrim(display_name)) between 1 and 30);

-- 舊版「整天有空」的表（上線時為空表），由時段表取代。
drop table if exists public.availability cascade;

create table if not exists public.availability_slots (
  id uuid primary key default gen_random_uuid(),
  caregiver_id uuid not null references public.members(id) on delete cascade,
  available_on date not null,
  starts_at time not null,
  ends_at time not null,
  note text check (note is null or char_length(note) <= 60),
  created_at timestamptz not null default now(),
  constraint availability_slots_valid_range check (ends_at > starts_at),
  -- 同一位保母同一天的時段不能重疊（不同保母之間互不影響）。
  constraint availability_slots_no_overlap exclude using gist (
    caregiver_id with =,
    tsrange(available_on + starts_at, available_on + ends_at) with &&
  )
);
create index if not exists availability_slots_day_idx on public.availability_slots(available_on);

alter table public.members enable row level security;
alter table public.availability_slots enable row level security;
revoke all on public.members, public.availability_slots from PUBLIC, anon, authenticated;

create schema if not exists calendar_private;
revoke all on schema calendar_private from PUBLIC, anon, authenticated;
-- 只讓下方明確授權的函式可被呼叫；這個 schema 不可加進 Data API 的 exposed schemas。
grant usage on schema calendar_private to anon, authenticated;

create table if not exists calendar_private.access_links (
  id uuid primary key default gen_random_uuid(),
  label text not null,
  role text not null check (role in ('owner', 'sitter')),
  caregiver_id uuid references public.members(id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  check ((role = 'owner' and caregiver_id is null) or
         (role = 'sitter' and caregiver_id is not null))
);
create index if not exists access_links_caregiver_idx on calendar_private.access_links(caregiver_id);
alter table calendar_private.access_links enable row level security;

create table if not exists calendar_private.changes (
  id bigint generated always as identity primary key,
  access_link_id uuid,
  selected_profile_id uuid not null,
  display_name text not null,
  operation text not null check (operation in ('register', 'cancel', 'rename')),
  available_on date,
  before_data jsonb,
  after_data jsonb,
  changed_at timestamptz not null default now()
);
alter table calendar_private.changes enable row level security;
create index if not exists changes_changed_at_idx on calendar_private.changes(changed_at desc);
revoke all on all tables in schema calendar_private from PUBLIC, anon, authenticated;
revoke all on all sequences in schema calendar_private from PUBLIC, anon, authenticated;

drop function if exists calendar_private.set_availability(text, date, boolean);
drop function if exists public.calendar_set_availability(text, date, boolean);

create or replace function calendar_private.authorize_link(p_token text)
returns calendar_private.access_links
language plpgsql stable security invoker set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = '28000', message = '專屬連結不完整，請重新開啟管理者提供的連結。';
  end if;
  select a.* into access_record from calendar_private.access_links a
  where a.token_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_token, 'UTF8')), 'hex')
    and a.revoked_at is null;
  if not found then
    raise exception using errcode = '28000', message = '這個專屬連結已失效，請向管理者索取新連結。';
  end if;
  if access_record.role = 'sitter' and not exists (
    select 1 from public.members m where m.id = access_record.caregiver_id and m.role = 'sitter'
  ) then
    raise exception using errcode = '28000', message = '這位保母已不在名單，請聯絡管理者。';
  end if;
  return access_record;
end;
$$;
revoke all on function calendar_private.authorize_link(text) from PUBLIC, anon, authenticated;

-- 主人連結看到所有保母；保母連結只看到自己的時段。
create or replace function calendar_private.read_calendar(p_token text, p_start date, p_end date)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare
  access_record calendar_private.access_links;
  profile_rows jsonb;
  slot_rows jsonb;
begin
  access_record := calendar_private.authorize_link(p_token);
  if p_start is null or p_end is null or not pg_catalog.isfinite(p_start)
    or not pg_catalog.isfinite(p_end) or p_end < p_start or p_end - p_start > 62 then
    raise exception using errcode = '22023', message = '請選擇有效的月份。';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', m.id, 'display_name', m.display_name)
    order by m.created_at, m.id), '[]'::jsonb)
  into profile_rows from public.members m
  where m.role = 'sitter' and (access_record.role = 'owner' or m.id = access_record.caregiver_id);
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', s.id, 'caregiver_id', s.caregiver_id, 'available_on', s.available_on,
      'starts_at', pg_catalog.to_char(s.starts_at, 'HH24:MI'),
      'ends_at', pg_catalog.to_char(s.ends_at, 'HH24:MI'), 'note', s.note)
    order by s.available_on, s.starts_at, s.caregiver_id), '[]'::jsonb)
  into slot_rows from public.availability_slots s join public.members m on m.id = s.caregiver_id
  where s.available_on between p_start and p_end and m.role = 'sitter'
    and (access_record.role = 'owner' or s.caregiver_id = access_record.caregiver_id);
  return jsonb_build_object('role', access_record.role, 'profile_id', access_record.caregiver_id,
    'profiles', profile_rows, 'slots', slot_rows);
end;
$$;

-- 一次登記多天同一個時段；caregiver_id 一律取自連結，瀏覽器傳不進別人的 id。
create or replace function calendar_private.add_slots(
  p_token text, p_dates date[], p_start_time time, p_end_time time, p_note text)
returns integer language plpgsql security definer set search_path = ''
as $$
declare
  access_record calendar_private.access_links;
  today date := (pg_catalog.now() at time zone 'Asia/Taipei')::date;
  inserted integer;
begin
  access_record := calendar_private.authorize_link(p_token);
  if access_record.role <> 'sitter' then
    raise exception using errcode = '42501', message = '主人連結只能查看空檔。';
  end if;
  if p_dates is null or coalesce(pg_catalog.array_length(p_dates, 1), 0) not between 1 and 62 then
    raise exception using errcode = '22023', message = '請選擇 1 到 62 天。';
  end if;
  if exists (select 1 from pg_catalog.unnest(p_dates) d
             where d is null or not pg_catalog.isfinite(d) or d < today or d > today + 400) then
    raise exception using errcode = '22023', message = '只能登記今天到一年內的日期。';
  end if;
  if p_start_time is null or p_end_time is null or p_end_time <= p_start_time then
    raise exception using errcode = '22023', message = '結束時間要晚於開始時間。';
  end if;
  if p_note is not null and char_length(btrim(p_note)) > 60 then
    raise exception using errcode = '22023', message = '備註最多 60 個字。';
  end if;
  perform pg_catalog.set_config('calendar.access_id', access_record.id::text, true);
  begin
    insert into public.availability_slots(caregiver_id, available_on, starts_at, ends_at, note)
    select access_record.caregiver_id, d, p_start_time, p_end_time, nullif(btrim(p_note), '')
    from (select distinct d from pg_catalog.unnest(p_dates) d) days;
    get diagnostics inserted = row_count;
  exception when exclusion_violation then
    raise exception using errcode = '23P01', message = '有些日期和你已登記的時段重疊，請先取消舊時段或換個時間。';
  end;
  return inserted;
end;
$$;

-- 只刪得掉自己的時段：條件同時比對時段 id 與連結對應的保母。
create or replace function calendar_private.remove_slot(p_token text, p_slot_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  access_record := calendar_private.authorize_link(p_token);
  if access_record.role <> 'sitter' then
    raise exception using errcode = '42501', message = '主人連結只能查看空檔。';
  end if;
  perform pg_catalog.set_config('calendar.access_id', access_record.id::text, true);
  delete from public.availability_slots
  where id = p_slot_id and caregiver_id = access_record.caregiver_id;
  if not found then
    raise exception using errcode = '42501', message = '找不到這個時段，或它不是你登記的。';
  end if;
  return true;
end;
$$;

create or replace function calendar_private.rename_profile(p_token text, p_name text)
returns text language plpgsql security definer set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  access_record := calendar_private.authorize_link(p_token);
  if access_record.role <> 'sitter' then
    raise exception using errcode = '42501', message = '主人連結無法修改保母名字。';
  end if;
  if p_name is null or char_length(btrim(p_name)) not between 1 and 30 then
    raise exception using errcode = '22023', message = '名字請填寫 1 到 30 個字。';
  end if;
  perform pg_catalog.set_config('calendar.access_id', access_record.id::text, true);
  update public.members set display_name = btrim(p_name)
  where id = access_record.caregiver_id and role = 'sitter';
  return btrim(p_name);
end;
$$;

-- 瀏覽器唯一能呼叫的 API：每個都必須帶有效的專屬連結 token。
create or replace function public.calendar_read(p_token text, p_start date, p_end date)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select calendar_private.read_calendar(p_token, p_start, p_end); $$;
create or replace function public.calendar_add_slots(
  p_token text, p_dates date[], p_start_time time, p_end_time time, p_note text)
returns integer language sql security invoker set search_path = ''
as $$ select calendar_private.add_slots(p_token, p_dates, p_start_time, p_end_time, p_note); $$;
create or replace function public.calendar_remove_slot(p_token text, p_slot_id uuid)
returns boolean language sql security invoker set search_path = ''
as $$ select calendar_private.remove_slot(p_token, p_slot_id); $$;
create or replace function public.calendar_rename(p_token text, p_name text)
returns text language sql security invoker set search_path = ''
as $$ select calendar_private.rename_profile(p_token, p_name); $$;

revoke all on function calendar_private.read_calendar(text, date, date),
  calendar_private.add_slots(text, date[], time, time, text),
  calendar_private.remove_slot(text, uuid),
  calendar_private.rename_profile(text, text),
  public.calendar_read(text, date, date),
  public.calendar_add_slots(text, date[], time, time, text),
  public.calendar_remove_slot(text, uuid),
  public.calendar_rename(text, text) from PUBLIC;
grant execute on function calendar_private.read_calendar(text, date, date),
  calendar_private.add_slots(text, date[], time, time, text),
  calendar_private.remove_slot(text, uuid),
  calendar_private.rename_profile(text, text),
  public.calendar_read(text, date, date),
  public.calendar_add_slots(text, date[], time, time, text),
  public.calendar_remove_slot(text, uuid),
  public.calendar_rename(text, text) to anon, authenticated;

-- 管理者專用（只在 SQL Editor 執行）：產生一條專屬連結，回傳的 token 只會出現這一次。
create or replace function calendar_private.create_access_link(
  p_label text, p_role text, p_caregiver_id uuid default null)
returns text language plpgsql security definer set search_path = ''
as $$
declare raw_token text := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
begin
  insert into calendar_private.access_links(label, role, caregiver_id, token_hash)
  values (p_label, p_role, p_caregiver_id,
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(raw_token, 'UTF8')), 'hex'));
  return raw_token;
end;
$$;
revoke all on function calendar_private.create_access_link(text, text, uuid) from PUBLIC, anon, authenticated;

-- 每次登記、取消、改名都留紀錄（誰、哪條連結、改了什麼），與異動同一個交易寫入。
create or replace function calendar_private.record_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  row_data jsonb;
  profile_id uuid;
  profile_name text;
  action_name text;
  date_value date;
begin
  if tg_op = 'DELETE' then row_data := to_jsonb(old);
  else row_data := to_jsonb(new);
  end if;
  if tg_table_name = 'members' then
    profile_id := (row_data ->> 'id')::uuid;
    profile_name := row_data ->> 'display_name';
    action_name := 'rename';
  else
    profile_id := (row_data ->> 'caregiver_id')::uuid;
    date_value := (row_data ->> 'available_on')::date;
    select m.display_name into profile_name from public.members m where m.id = profile_id;
    action_name := case when tg_op = 'DELETE' then 'cancel' else 'register' end;
  end if;
  insert into calendar_private.changes (
    access_link_id, selected_profile_id, display_name, operation,
    available_on, before_data, after_data
  ) values (
    nullif(pg_catalog.current_setting('calendar.access_id', true), '')::uuid,
    profile_id, coalesce(profile_name, '已移除的保母'), action_name, date_value,
    case when tg_op <> 'INSERT' then to_jsonb(old) end,
    case when tg_op <> 'DELETE' then to_jsonb(new) end
  );
  return null;
end;
$$;
revoke all on function calendar_private.record_change() from PUBLIC, anon, authenticated;
drop trigger if exists slot_change_log on public.availability_slots;
create trigger slot_change_log after insert or delete on public.availability_slots
  for each row execute function calendar_private.record_change();
drop trigger if exists member_name_change_log on public.members;
create trigger member_name_change_log after update of display_name on public.members
  for each row when (old.display_name is distinct from new.display_name)
  execute function calendar_private.record_change();

insert into public.members(display_name, role)
select name, 'sitter' from (values ('佑宥'), ('楚涵')) names(name)
where not exists (select 1 from public.members m where m.display_name = names.name and m.role = 'sitter');

-- ── 選名字＋4 位數 PIN 登入 ──
-- PIN 以 bcrypt 雜湊存放；同一人連錯 5 次鎖 15 分鐘。登入成功會發一個 session token，
-- 存進 access_links，之後所有權限檢查都和專屬連結走同一套。
alter table public.members add column if not exists pin_hash text;
alter table public.members add column if not exists failed_pins integer not null default 0;
alter table public.members add column if not exists locked_until timestamptz;
alter table calendar_private.access_links add column if not exists member_id uuid references public.members(id) on delete cascade;

-- 登入畫面的名單：只列出已設定 PIN 的人。
create or replace function calendar_private.directory()
returns jsonb language sql stable security definer set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', m.id, 'display_name', m.display_name, 'role', m.role)
    order by m.role desc, m.created_at, m.id), '[]'::jsonb)
  from public.members m where m.pin_hash is not null;
$$;

-- 錯誤時回傳 {error} 而不是 raise，否則失敗次數會跟著交易一起回滾、鎖定就沒作用。
create or replace function calendar_private.login(p_member_id uuid, p_pin text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  m public.members;
  raw_token text;
  next_fails integer;
begin
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('error', '請輸入 4 位數字密碼。');
  end if;
  select * into m from public.members where id = p_member_id for update;
  if not found or m.pin_hash is null then
    return jsonb_build_object('error', '找不到這個人，請聯絡管理者。');
  end if;
  if m.locked_until is not null and m.locked_until > pg_catalog.now() then
    return jsonb_build_object('error', '密碼錯太多次，請 15 分鐘後再試。');
  end if;
  if extensions.crypt(p_pin, m.pin_hash) <> m.pin_hash then
    next_fails := case when m.locked_until is not null then 1 else m.failed_pins + 1 end;
    update public.members set failed_pins = next_fails,
      locked_until = case when next_fails >= 5 then pg_catalog.now() + interval '15 minutes' end
    where id = m.id;
    return jsonb_build_object('error', case when next_fails >= 5 then '密碼錯太多次，請 15 分鐘後再試。'
      else '密碼不對，請再試一次。' end);
  end if;
  update public.members set failed_pins = 0, locked_until = null where id = m.id;
  raw_token := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  insert into calendar_private.access_links(label, role, caregiver_id, member_id, token_hash)
  values ('PIN 登入', m.role, case when m.role = 'sitter' then m.id end, m.id,
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(raw_token, 'UTF8')), 'hex'));
  return jsonb_build_object('token', raw_token);
end;
$$;

create or replace function calendar_private.logout(p_token text)
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  if p_token is null or p_token !~ '^[0-9a-f]{64}$' then return false; end if;
  update calendar_private.access_links set revoked_at = pg_catalog.now()
  where token_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_token, 'UTF8')), 'hex')
    and revoked_at is null;
  return found;
end;
$$;

-- 管理者專用（只在 SQL Editor 執行）：設定或重設 PIN，同時讓這個人所有裝置登出。
create or replace function calendar_private.set_pin(p_member_id uuid, p_pin text)
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    raise exception using errcode = '22023', message = 'PIN 必須是 4 位數字。';
  end if;
  update public.members set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf')),
    failed_pins = 0, locked_until = null
  where id = p_member_id;
  if not found then raise exception using errcode = '22023', message = '找不到這個成員。'; end if;
  update calendar_private.access_links set revoked_at = pg_catalog.now()
  where (member_id = p_member_id or caregiver_id = p_member_id) and revoked_at is null;
end;
$$;
revoke all on function calendar_private.set_pin(uuid, text) from PUBLIC, anon, authenticated;

create or replace function public.calendar_directory()
returns jsonb language sql stable security invoker set search_path = ''
as $$ select calendar_private.directory(); $$;
create or replace function public.calendar_login(p_member_id uuid, p_pin text)
returns jsonb language sql security invoker set search_path = ''
as $$ select calendar_private.login(p_member_id, p_pin); $$;
create or replace function public.calendar_logout(p_token text)
returns boolean language sql security invoker set search_path = ''
as $$ select calendar_private.logout(p_token); $$;

revoke all on function calendar_private.directory(), calendar_private.login(uuid, text),
  calendar_private.logout(text), public.calendar_directory(),
  public.calendar_login(uuid, text), public.calendar_logout(text) from PUBLIC;
grant execute on function calendar_private.directory(), calendar_private.login(uuid, text),
  calendar_private.logout(text), public.calendar_directory(),
  public.calendar_login(uuid, text), public.calendar_logout(text) to anon, authenticated;

insert into public.members(display_name, role)
select '主人', 'owner' where not exists (select 1 from public.members where role = 'owner');

-- ── 頭像（表情符號）與個人設定 ──
alter table public.members add column if not exists avatar text;
alter table public.members drop constraint if exists members_avatar_length;
alter table public.members add constraint members_avatar_length
  check (avatar is null or char_length(avatar) between 1 and 8);

create or replace function calendar_private.directory()
returns jsonb language sql stable security definer set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', m.id, 'display_name', m.display_name, 'role', m.role, 'avatar', m.avatar)
    order by m.role desc, m.created_at, m.id), '[]'::jsonb)
  from public.members m where m.pin_hash is not null;
$$;

-- 取代前面的版本：多回傳頭像，以及登入者自己（me）。
create or replace function calendar_private.read_calendar(p_token text, p_start date, p_end date)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare
  access_record calendar_private.access_links;
  profile_rows jsonb;
  slot_rows jsonb;
  me_row jsonb;
begin
  access_record := calendar_private.authorize_link(p_token);
  if p_start is null or p_end is null or not pg_catalog.isfinite(p_start)
    or not pg_catalog.isfinite(p_end) or p_end < p_start or p_end - p_start > 62 then
    raise exception using errcode = '22023', message = '請選擇有效的月份。';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id', m.id, 'display_name', m.display_name, 'avatar', m.avatar)
    order by m.created_at, m.id), '[]'::jsonb)
  into profile_rows from public.members m
  where m.role = 'sitter' and (access_record.role = 'owner' or m.id = access_record.caregiver_id);
  select jsonb_build_object('id', m.id, 'display_name', m.display_name, 'avatar', m.avatar, 'role', m.role)
  into me_row from public.members m
  where m.id = coalesce(access_record.member_id, access_record.caregiver_id);
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', s.id, 'caregiver_id', s.caregiver_id, 'available_on', s.available_on,
      'starts_at', pg_catalog.to_char(s.starts_at, 'HH24:MI'),
      'ends_at', pg_catalog.to_char(s.ends_at, 'HH24:MI'), 'note', s.note)
    order by s.available_on, s.starts_at, s.caregiver_id), '[]'::jsonb)
  into slot_rows from public.availability_slots s join public.members m on m.id = s.caregiver_id
  where s.available_on between p_start and p_end and m.role = 'sitter'
    and (access_record.role = 'owner' or s.caregiver_id = access_record.caregiver_id);
  return jsonb_build_object('role', access_record.role, 'profile_id', access_record.caregiver_id,
    'me', me_row, 'profiles', profile_rows, 'slots', slot_rows);
end;
$$;

-- 改自己的名字和頭像（保母和主人都可以，但只能改登入的那個人）。
create or replace function calendar_private.update_profile(p_token text, p_name text, p_avatar text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  access_record calendar_private.access_links;
  target uuid;
  clean_avatar text := nullif(btrim(p_avatar), '');
begin
  access_record := calendar_private.authorize_link(p_token);
  target := coalesce(access_record.member_id, access_record.caregiver_id);
  if target is null then
    raise exception using errcode = '42501', message = '這個登入方式不能修改個人設定，請用名字＋PIN 登入。';
  end if;
  if p_name is null or char_length(btrim(p_name)) not between 1 and 30 then
    raise exception using errcode = '22023', message = '名字請填寫 1 到 30 個字。';
  end if;
  if clean_avatar is not null and (char_length(clean_avatar) > 8 or clean_avatar ~ '[<>&"''[:space:]]') then
    raise exception using errcode = '22023', message = '頭像請選一個表情符號。';
  end if;
  perform pg_catalog.set_config('calendar.access_id', access_record.id::text, true);
  update public.members set display_name = btrim(p_name), avatar = clean_avatar where id = target;
  return jsonb_build_object('display_name', btrim(p_name), 'avatar', clean_avatar);
end;
$$;

create or replace function public.calendar_update_profile(p_token text, p_name text, p_avatar text)
returns jsonb language sql security invoker set search_path = ''
as $$ select calendar_private.update_profile(p_token, p_name, p_avatar); $$;

revoke all on function calendar_private.update_profile(text, text, text),
  public.calendar_update_profile(text, text, text) from PUBLIC;
grant execute on function calendar_private.update_profile(text, text, text),
  public.calendar_update_profile(text, text, text) to anon, authenticated;

-- ── 主人管理成員：新增保母、設定／重設 PIN、移除保母 ──
create or replace function calendar_private.require_owner(p_token text)
returns calendar_private.access_links
language plpgsql stable security invoker set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  access_record := calendar_private.authorize_link(p_token);
  if access_record.role <> 'owner' then
    raise exception using errcode = '42501', message = '只有主人可以管理成員。';
  end if;
  return access_record;
end;
$$;
revoke all on function calendar_private.require_owner(text) from PUBLIC, anon, authenticated;

create or replace function calendar_private.list_members(p_token text)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  access_record := calendar_private.require_owner(p_token);
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', m.id, 'display_name', m.display_name, 'role', m.role, 'avatar', m.avatar,
      'has_pin', m.pin_hash is not null, 'is_me', m.id = access_record.member_id)
    order by m.role desc, m.created_at, m.id), '[]'::jsonb) from public.members m);
end;
$$;

create or replace function calendar_private.add_member(p_token text, p_name text, p_pin text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare new_id uuid;
begin
  perform calendar_private.require_owner(p_token);
  if p_name is null or char_length(btrim(p_name)) not between 1 and 30 then
    raise exception using errcode = '22023', message = '名字請填寫 1 到 30 個字。';
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    raise exception using errcode = '22023', message = 'PIN 必須是 4 位數字。';
  end if;
  if exists (select 1 from public.members m where lower(btrim(m.display_name)) = lower(btrim(p_name))) then
    raise exception using errcode = '23505', message = '已經有叫這個名字的人了，請換一個名字。';
  end if;
  insert into public.members(display_name, role) values (btrim(p_name), 'sitter') returning id into new_id;
  perform calendar_private.set_pin(new_id, p_pin);
  return new_id;
end;
$$;

-- 重設 PIN 會讓那個人所有裝置登出（包含主人改自己的 PIN）。
create or replace function calendar_private.set_member_pin(p_token text, p_member_id uuid, p_pin text)
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  perform calendar_private.require_owner(p_token);
  if not exists (select 1 from public.members where id = p_member_id) then
    raise exception using errcode = '22023', message = '找不到這個成員。';
  end if;
  perform calendar_private.set_pin(p_member_id, p_pin);
  return true;
end;
$$;

-- 只能移除保母（主人不能把自己刪掉）；他登記的時段會一起刪除。
create or replace function calendar_private.remove_member(p_token text, p_member_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare access_record calendar_private.access_links;
begin
  access_record := calendar_private.require_owner(p_token);
  perform pg_catalog.set_config('calendar.access_id', access_record.id::text, true);
  delete from public.members where id = p_member_id and role = 'sitter';
  if not found then
    raise exception using errcode = '22023', message = '只能移除保母。';
  end if;
  return true;
end;
$$;

create or replace function public.calendar_list_members(p_token text)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select calendar_private.list_members(p_token); $$;
create or replace function public.calendar_add_member(p_token text, p_name text, p_pin text)
returns uuid language sql security invoker set search_path = ''
as $$ select calendar_private.add_member(p_token, p_name, p_pin); $$;
create or replace function public.calendar_set_member_pin(p_token text, p_member_id uuid, p_pin text)
returns boolean language sql security invoker set search_path = ''
as $$ select calendar_private.set_member_pin(p_token, p_member_id, p_pin); $$;
create or replace function public.calendar_remove_member(p_token text, p_member_id uuid)
returns boolean language sql security invoker set search_path = ''
as $$ select calendar_private.remove_member(p_token, p_member_id); $$;

revoke all on function calendar_private.list_members(text), calendar_private.add_member(text, text, text),
  calendar_private.set_member_pin(text, uuid, text), calendar_private.remove_member(text, uuid),
  public.calendar_list_members(text), public.calendar_add_member(text, text, text),
  public.calendar_set_member_pin(text, uuid, text), public.calendar_remove_member(text, uuid) from PUBLIC;
grant execute on function calendar_private.list_members(text), calendar_private.add_member(text, text, text),
  calendar_private.set_member_pin(text, uuid, text), calendar_private.remove_member(text, uuid),
  public.calendar_list_members(text), public.calendar_add_member(text, text, text),
  public.calendar_set_member_pin(text, uuid, text), public.calendar_remove_member(text, uuid) to anon, authenticated;
commit;
