-- ============================================================
--  乐嗨轮盘 · 独立登录系统  (在你现有 Supabase 里跑一次即可)
--  与百家乐/智能轮盘完全隔离，互不影响
--  管理员初始密码：888888   （建表后请用最底部命令改掉）
-- ============================================================

-- 1) 加密扩展
create extension if not exists pgcrypto;

-- 2) 乐嗨轮盘用户表（独立，不碰 user_profiles）
create table if not exists lehai_users (
  username    text primary key,
  pwd         text        not null,           -- bcrypt 加密后的密码
  note        text,
  is_active   boolean     not null default true,
  expiry_at   timestamptz not null,
  device_id   text,
  last_login  timestamptz,
  created_at  timestamptz not null default now()
);
alter table lehai_users enable row level security;   -- 锁死：anon 不能直接读写，只能走下面的函数

-- 3) 配置表（存管理员密码哈希）
create table if not exists lehai_meta (
  k text primary key,
  v text not null
);
alter table lehai_meta enable row level security;
insert into lehai_meta(k, v)
  values ('admin_pw', crypt('888888', gen_salt('bf')))
  on conflict (k) do nothing;

-- ---------- 内部：校验管理员密码 ----------
create or replace function lehai_is_admin(p_admin text)
returns boolean language sql security definer set search_path = public, pg_temp as $$
  select exists(select 1 from lehai_meta where k='admin_pw' and v = crypt(p_admin, v));
$$;

-- ---------- 用户登录 ----------
create or replace function lehai_login(p_username text, p_password text, p_device text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
declare u lehai_users;
begin
  select * into u from lehai_users where username = lower(p_username);
  if not found then return json_build_object('success',false,'error','用户名或密码错误'); end if;
  if u.pwd <> crypt(p_password, u.pwd) then return json_build_object('success',false,'error','用户名或密码错误'); end if;
  if not u.is_active then return json_build_object('success',false,'error','账号已被禁用，请联系管理员'); end if;
  if now() > u.expiry_at then return json_build_object('success',false,'error','账号已过期，请联系管理员续费'); end if;
  if u.device_id is not null and u.device_id <> p_device then
    return json_build_object('success',false,'error','该账号已在其他设备使用');
  end if;
  if u.device_id is null then
    update lehai_users set device_id = p_device, last_login = now() where username = u.username;
  else
    update lehai_users set last_login = now() where username = u.username;
  end if;
  return json_build_object('success',true,'expiry',u.expiry_at,'note',u.note);
end; $$;

-- ---------- 运行中复查（过期/禁用/换设备） ----------
create or replace function lehai_check(p_username text, p_device text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
declare u lehai_users;
begin
  select * into u from lehai_users where username = lower(p_username);
  if not found then return json_build_object('ok',false,'reason','账号信息丢失，请重新登录'); end if;
  if not u.is_active then return json_build_object('ok',false,'reason','账号已被禁用'); end if;
  if now() > u.expiry_at then return json_build_object('ok',false,'reason','账号已过期'); end if;
  if u.device_id is not null and u.device_id <> p_device then
    return json_build_object('ok',false,'reason','该账号已在其他设备使用');
  end if;
  update lehai_users set last_login = now() where username = u.username;   -- 心跳：记录最后在线
  return json_build_object('ok',true);
end; $$;

-- ---------- 后台：用户列表 ----------
create or replace function lehai_admin_list(p_admin text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  return json_build_object('success',true,'users',
    coalesce((select json_agg(t order by t.created_at desc) from
      (select username,note,is_active,expiry_at,device_id,last_login,created_at from lehai_users) t),'[]'::json));
end; $$;

-- ---------- 后台：创建用户 ----------
create or replace function lehai_admin_create(p_admin text, p_username text, p_password text, p_note text, p_days int)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
declare exp timestamptz;
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  if exists(select 1 from lehai_users where username = lower(p_username)) then
    return json_build_object('success',false,'error','用户名已存在');
  end if;
  exp := now() + (p_days || ' days')::interval;
  insert into lehai_users(username,pwd,note,is_active,expiry_at)
    values (lower(p_username), crypt(p_password, gen_salt('bf')), p_note, true, exp);
  return json_build_object('success',true,'expiry',exp);
end; $$;

-- ---------- 后台：续期 ----------
create or replace function lehai_admin_renew(p_admin text, p_username text, p_days int)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
declare cur timestamptz; base timestamptz; exp timestamptz;
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  select expiry_at into cur from lehai_users where username = lower(p_username);
  if not found then return json_build_object('success',false,'error','用户不存在'); end if;
  base := greatest(cur, now());                 -- 未过期则在原到期日上累加
  exp  := base + (p_days || ' days')::interval;
  update lehai_users set expiry_at = exp, is_active = true where username = lower(p_username);
  return json_build_object('success',true,'expiry',exp);
end; $$;

-- ---------- 后台：重置密码 ----------
create or replace function lehai_admin_reset(p_admin text, p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  update lehai_users set pwd = crypt(p_password, gen_salt('bf')) where username = lower(p_username);
  if not found then return json_build_object('success',false,'error','用户不存在'); end if;
  return json_build_object('success',true);
end; $$;

-- ---------- 后台：解绑设备 ----------
create or replace function lehai_admin_unbind(p_admin text, p_username text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  update lehai_users set device_id = null where username = lower(p_username);
  if not found then return json_build_object('success',false,'error','用户不存在'); end if;
  return json_build_object('success',true);
end; $$;

-- ---------- 后台：启用 / 停用账号（实时停止使用） ----------
create or replace function lehai_admin_active(p_admin text, p_username text, p_active boolean)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  update lehai_users set is_active = p_active where username = lower(p_username);
  if not found then return json_build_object('success',false,'error','用户不存在'); end if;
  return json_build_object('success',true);
end; $$;

-- ---------- 后台：删除用户 ----------
create or replace function lehai_admin_delete(p_admin text, p_username text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin) then return json_build_object('success',false,'error','管理员密码错误'); end if;
  delete from lehai_users where username = lower(p_username);
  return json_build_object('success',true);
end; $$;

-- ---------- 后台：修改管理员密码 ----------
create or replace function lehai_admin_setpw(p_admin_old text, p_admin_new text)
returns json language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not lehai_is_admin(p_admin_old) then return json_build_object('success',false,'error','原管理员密码错误'); end if;
  update lehai_meta set v = crypt(p_admin_new, gen_salt('bf')) where k='admin_pw';
  return json_build_object('success',true);
end; $$;

-- 4) 授权 anon / 登录用户 调用这些函数（网页用 publishable key）
grant execute on function lehai_login(text,text,text)        to anon, authenticated;
grant execute on function lehai_check(text,text)             to anon, authenticated;
grant execute on function lehai_admin_list(text)             to anon, authenticated;
grant execute on function lehai_admin_create(text,text,text,text,int) to anon, authenticated;
grant execute on function lehai_admin_renew(text,text,int)   to anon, authenticated;
grant execute on function lehai_admin_reset(text,text,text)  to anon, authenticated;
grant execute on function lehai_admin_unbind(text,text)      to anon, authenticated;
grant execute on function lehai_admin_active(text,text,boolean) to anon, authenticated;
grant execute on function lehai_admin_delete(text,text)      to anon, authenticated;
grant execute on function lehai_admin_setpw(text,text)       to anon, authenticated;

-- ============================================================
-- 跑完以上即可。管理员初始密码 888888。
-- 想改管理员密码，单独跑下面这行（把 你的新密码 换掉）：
--   select lehai_admin_setpw('888888','你的新密码');
-- ============================================================
