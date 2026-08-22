-- =============================================================================
-- V2 — RBAC: role, การมอบ role ให้ user, และการยืนยันอีเมล
-- =============================================================================
-- โมเดลแบ่งเป็น 2 ชั้น (docs อ้างอิง: vertex-pet-service/docs/REFACTOR_PLAN.md §Phase 1A.1)
--   ชั้นที่ 1 Global RBAC  — อยู่ที่นี่ ส่งไปกับ JWT claim "roles"
--   ชั้นที่ 2 Resource ACL — อยู่ที่ pet-service (pet_caregivers + caregiver_permissions)
--
-- JWT พกแค่ roles ไม่พก permission list → token เล็ก และแต่ละ service
-- map role → capability ในตารางของตัวเอง โดยไม่ต้องผูกกับ auth-service
-- =============================================================================

CREATE TABLE IF NOT EXISTS roles (
    code        varchar(50)  NOT NULL,
    name        varchar(200) NOT NULL,
    description text,
    -- is_system = true ห้ามลบหรือแก้ผ่าน UI เพราะโค้ดอ้างถึงโดยตรง
    is_system   boolean      NOT NULL DEFAULT false,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT roles_pkey PRIMARY KEY (code)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id    uuid        NOT NULL,
    role_code  varchar(50) NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by uuid,
    CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_code),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_code)
        REFERENCES roles (code)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role_code);

-- bootstrap_admins คือรายชื่อที่ได้ role อัตโนมัติเมื่อบัญชีพร้อม
--
-- 🔐 แก้ผ่าน migration เท่านั้น ห้ามเปิดให้ API ใดเขียนตารางนี้
--    ถ้าเขียนได้ผ่าน API ก็เท่ากับมีทางลัดไปสู่ SUPER_ADMIN
CREATE TABLE IF NOT EXISTS bootstrap_admins (
    email      varchar(320) NOT NULL,
    role_code  varchar(50)  NOT NULL,
    note       text,
    granted_at timestamptz,
    created_at timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT bootstrap_admins_pkey PRIMARY KEY (email),
    CONSTRAINT fk_bootstrap_admins_role FOREIGN KEY (role_code)
        REFERENCES roles (code)
);

-- ⚠️ email_verified จำเป็นต่อความปลอดภัยของการ bootstrap admin
--
-- handleSignup สมัครด้วย email + password ได้ทันทีโดยไม่มีการยืนยันอีเมลเลย
-- ถ้าให้สิทธิ์โดยดูแค่สตริงอีเมล คนอื่นสมัครด้วยอีเมลนั้นชิง SUPER_ADMIN ไปได้
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;

-- บัญชีที่เคย login ผ่าน Google ถือว่าอีเมลถูกยืนยันแล้ว
-- (Google เป็นคนยืนยันให้ และ idtoken.Validate ตรวจลายเซ็นแล้ว)
UPDATE users SET email_verified = true
WHERE id IN (SELECT user_id FROM oauth_identities WHERE provider = 'google');

-- index สำหรับการค้นหาแบบไม่สนตัวพิมพ์ (ใช้ตอน bootstrap admin และ lookup)
--
-- 🔸 จงใจไม่ทำเป็น UNIQUE ในเฟสนี้
--    ถ้ามีบัญชีเดิมที่อีเมลต่างกันแค่ตัวพิมพ์อยู่แล้ว การสร้าง unique index จะทำให้
--    migration ล้มและ deploy ค้างทั้งชุด ซึ่งขัดกับเป้าหมาย "ผู้ใช้เดิมต้องใช้งานได้"
--    การกันสมัครซ้ำด้วยตัวพิมพ์ต่างกันเป็นงานแยก ต้องตรวจข้อมูลจริงก่อน:
--      SELECT lower(email), count(*) FROM users GROUP BY 1 HAVING count(*) > 1;
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));

-- --- seed role ขั้นต่ำที่ migration ถัดไปต้องใช้ ---------------------------
--
-- ⚠️ ต้อง seed ตรงนี้ ไม่ใช่ปล่อยให้ R__0010_roles.sql ทำอย่างเดียว
--    เพราะ Flyway รัน R__ ทั้งหมด "หลัง" V__ ทั้งหมดเสมอ
--    V3 ที่อ้าง role_code = 'SUPER_ADMIN' จึงจะล้มด้วย foreign key violation
--    ถ้ารอ R__ มา seed ให้
--
--    กฎทั่วไป: V__ ห้ามพึ่งพาข้อมูลที่ R__ เป็นคน seed
--
-- R__0010_roles.sql ยังคงมีอยู่และเป็นตัวรักษาให้ตารางตรงกับ git ต่อไป
INSERT INTO roles (code, name, description, is_system) VALUES
    ('SUPER_ADMIN', 'Super Administrator', 'ทำได้ทุกอย่างในทุก service', true),
    ('PET_ADMIN',   'Pet Administrator',   'จัดการข้อมูลสัตว์เลี้ยงและ master data', true),
    ('USER',        'General User',        'ผู้ใช้ทั่วไป จัดการเฉพาะข้อมูลของตัวเอง', true)
ON CONFLICT (code) DO NOTHING;
