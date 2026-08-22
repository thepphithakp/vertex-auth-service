-- =============================================================================
-- Repeatable — รายการ role ของระบบ
-- =============================================================================
-- ✅ ใช้ R__ ได้ เพราะเป็นข้อมูลชั้น code-owned
--    โค้ดอ้างถึง role code เหล่านี้โดยตรง การเพิ่ม role ใหม่จึงต้องมาคู่กับ code change
--    และไม่เปิดให้แก้ผ่าน UI → ไม่มีอะไรให้เขียนทับ
--
-- ต่างจากการ "มอบ role ให้ user" (user_roles) ซึ่งเป็นข้อมูลที่ admin แก้ผ่าน UI ได้
-- จึงห้ามอยู่ในไฟล์ R__ เด็ดขาด
-- =============================================================================

INSERT INTO roles (code, name, description, is_system) VALUES
    ('SUPER_ADMIN', 'Super Administrator', 'ทำได้ทุกอย่างในทุก service', true),
    ('PET_ADMIN',   'Pet Administrator',   'จัดการข้อมูลสัตว์เลี้ยงและ master data', true),
    ('USER',        'General User',        'ผู้ใช้ทั่วไป จัดการเฉพาะข้อมูลของตัวเอง', true)
ON CONFLICT (code) DO UPDATE SET
    name        = EXCLUDED.name,
    description = EXCLUDED.description,
    is_system   = EXCLUDED.is_system;
