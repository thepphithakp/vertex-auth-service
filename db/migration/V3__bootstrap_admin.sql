-- =============================================================================
-- V3 — กำหนดผู้ดูแลระบบคนแรก
-- =============================================================================
-- 🔐 กติกาความปลอดภัยที่ห้ามละเมิด
--
-- handleSignup (main.go) สมัครด้วย email + password ได้ทันทีโดยไม่ยืนยันอีเมล
-- ถ้า grant สิทธิ์โดยดูแค่สตริงอีเมล จะเปิดช่องให้:
--   คนอื่นสมัครบัญชีด้วยอีเมลที่อยู่ในรายการนี้ก่อน แล้วได้ SUPER_ADMIN ทันที
--
-- จึงให้สิทธิ์เฉพาะบัญชีที่ email_verified = true เท่านั้น
-- ซึ่งตอนนี้เป็นจริงได้ทางเดียวคือเคย login ผ่าน Google
-- (ดู reconcileBootstrapAdmin ใน rbac.go ที่บังคับกฎเดียวกันตอน runtime)
-- =============================================================================

INSERT INTO bootstrap_admins (email, role_code, note) VALUES
    ('thappithakpluemacting@gmail.com', 'SUPER_ADMIN', 'เจ้าของระบบคนแรก')
ON CONFLICT (email) DO NOTHING;

-- grant ให้บัญชีที่มีอยู่แล้วและยืนยันอีเมลแล้ว
INSERT INTO user_roles (user_id, role_code)
SELECT u.id, b.role_code
FROM users u
JOIN bootstrap_admins b ON lower(u.email) = lower(b.email)
WHERE u.email_verified = true
ON CONFLICT DO NOTHING;

UPDATE bootstrap_admins b SET granted_at = now()
WHERE b.granted_at IS NULL
  AND EXISTS (
      SELECT 1 FROM users u
      WHERE lower(u.email) = lower(b.email) AND u.email_verified = true
  );

-- ทุกคนที่เหลือได้ role USER
-- ทำให้ตาราง user_roles เป็นแหล่งข้อมูลเดียวจริงๆ ไม่ต้องเดาจากการไม่มีแถว
INSERT INTO user_roles (user_id, role_code)
SELECT u.id, 'USER' FROM users u
ON CONFLICT DO NOTHING;

-- --- รายงานผลให้คนที่รัน migration เห็นทันที -----------------------------
DO $$
DECLARE
    admin_count int;
    pending     text;
BEGIN
    SELECT count(*) INTO admin_count FROM user_roles WHERE role_code = 'SUPER_ADMIN';

    SELECT string_agg(b.email, ', ') INTO pending
    FROM bootstrap_admins b
    WHERE b.granted_at IS NULL;

    RAISE NOTICE 'จำนวน SUPER_ADMIN ในระบบ: %', admin_count;

    IF pending IS NOT NULL THEN
        RAISE WARNING 'ยังไม่ได้ grant: % — บัญชียังไม่ถูกสร้าง หรือยังไม่ได้ยืนยันอีเมล', pending;
        RAISE WARNING 'ให้ login ผ่าน Google ด้วยอีเมลนั้นหนึ่งครั้ง แล้วระบบจะ grant ให้อัตโนมัติ';
    END IF;

    IF admin_count = 0 THEN
        RAISE WARNING '⚠️  ยังไม่มี SUPER_ADMIN — backoffice จะเข้าหน้า admin ไม่ได้';
        RAISE WARNING '    ห้าม deploy pet-service ที่บังคับ RBAC จนกว่าจะมีอย่างน้อย 1 คน';
    END IF;
END $$;
