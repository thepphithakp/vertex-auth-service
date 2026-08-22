-- =============================================================================
-- V1 — Baseline: schema ที่ GORM AutoMigrate สร้างไว้ ณ วันที่เริ่มใช้ Flyway
-- =============================================================================
-- ⚠️ ห้ามแก้ไฟล์นี้หลังจากถูก apply บน environment ใดแล้ว
--
-- บน database ที่มีข้อมูลอยู่แล้ว: FLYWAY_BASELINE_ON_MIGRATE=true จะ mark
-- migration นี้ว่า applied โดยไม่รัน → ตารางเดิมไม่ถูกแตะ
--
-- 📌 auth-service ยังใช้ schema public อยู่ (ต่างจาก pet-service ที่ย้ายไป pet แล้ว)
--    การย้ายไป schema auth เป็นงานของ Phase 9 ซึ่งมี runbook แยก
--    ตอนนี้ใช้ FLYWAY_TABLE=flyway_schema_history_auth เพื่อไม่ให้ชนกับ service อื่น
--    ที่ใช้ database เดียวกัน
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    email         text NOT NULL,
    password_hash text,
    full_name     text,
    created_at    timestamptz,
    updated_at    timestamptz,
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- ⚠️ ชื่อตารางคือ o_auth_identities ไม่ใช่ oauth_identities
-- GORM แปลงชื่อ struct OAuthIdentity เป็น snake_case ได้แบบนี้ (O|Auth|Identity)
-- ยืนยันกับ production จริงแล้ว — เขียนผิดจะทำให้ migration ถัดไปล้ม
CREATE TABLE IF NOT EXISTS o_auth_identities (
    id          uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL,
    provider    varchar(50)  NOT NULL,
    provider_id varchar(255) NOT NULL,
    created_at  timestamptz,
    CONSTRAINT o_auth_identities_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_o_auth_identities_user_id ON o_auth_identities (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_provider_id
    ON o_auth_identities (provider, provider_id);
