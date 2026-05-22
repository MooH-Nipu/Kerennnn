-- Multi-user auth table for Charlie kerennnn SOC toolbox
create table app_users (
  id           uuid primary key default gen_random_uuid(),
  username     text unique not null,
  password_hash text not null,
  role         text not null check (role in ('admin', 'pac', 'charlie', 'l1', 'l2')),
  created_at   timestamptz default now(),
  created_by   uuid references app_users(id)
);

-- Seed the first admin account.
-- 1. Generate a bcrypt hash (cost 12) for your chosen password:
--    node -e "const b = require('bcryptjs'); b.hash('YOUR_PASSWORD', 12).then(console.log)"
-- 2. Replace <hash> below and run this INSERT:
--
-- insert into app_users (username, password_hash, role)
-- values ('admin', '<hash>', 'admin');
