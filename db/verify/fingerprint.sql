-- Fingerprint ของ auth-service — รันก่อนและหลังทุกครั้งที่แตะข้อมูล
\pset format unaligned
\pset fieldsep |

SELECT 'users' AS tbl, count(*) AS n,
       md5(coalesce(string_agg(id::text, ',' ORDER BY id), '')) AS id_hash,
       md5(coalesce(string_agg(md5(u.*::text), ',' ORDER BY u.id), '')) AS row_hash
FROM users u
UNION ALL
SELECT 'oauth_identities', count(*),
       md5(coalesce(string_agg(id::text, ',' ORDER BY id), '')),
       md5(coalesce(string_agg(md5(o.*::text), ',' ORDER BY o.id), ''))
FROM oauth_identities o
ORDER BY tbl;

\echo '--- ใครมี role อะไรบ้าง ---'
SELECT u.email, ur.role_code, ur.granted_at
FROM user_roles ur JOIN users u ON u.id = ur.user_id
WHERE ur.role_code <> 'USER'
ORDER BY ur.role_code, u.email;

\echo '--- bootstrap admin ที่ยังไม่ได้ grant ---'
SELECT email, role_code, note FROM bootstrap_admins WHERE granted_at IS NULL;
