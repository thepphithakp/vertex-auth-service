package port

import (
	"context"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
)

// RoleRepository อ่านและเขียน role ของผู้ใช้
type RoleRepository interface {
	// RolesForUser อ่าน role ทั้งหมดของผู้ใช้ เรียงตาม role_code
	//
	// ⚠️ ไม่คืน error โดยตั้งใจ — คืน [USER] ทั้งกรณีไม่มีแถวและกรณี query ล้ม
	//    (ล้มแล้ว log ไว้) เป็นพฤติกรรมเดิมที่ /me และหน้า admin พึ่งพาอยู่
	//    การเปลี่ยนให้คืน error จะเปลี่ยนสถานะ HTTP ของ endpoint เหล่านั้น
	RolesForUser(ctx context.Context, userID uuid.UUID) []string

	// EnsureDefaultRole ให้ role USER กับบัญชีที่เพิ่งสร้าง
	//
	// ⚠️ ไม่คืน error โดยตั้งใจ เหมือน RolesForUser — เดิมล้มแล้วแค่ log
	//    แล้วปล่อยให้ signup/login สำเร็จต่อ เพราะ RolesForUser มี [USER]
	//    เป็นค่าตั้งต้นให้อยู่แล้ว
	EnsureDefaultRole(ctx context.Context, userID uuid.UUID)

	// ListRoles คืน role ทั้งหมดในระบบ เรียงตาม code
	ListRoles(ctx context.Context) ([]domain.Role, error)

	// ValidRoleCodes คืนเซ็ตของ role code ที่มีอยู่จริง ใช้ตรวจค่าที่ผู้เรียกส่งมา
	ValidRoleCodes(ctx context.Context) (map[string]bool, error)

	// SetRoles แทนที่ role ของผู้ใช้ทั้งชุดในทรานแซกชันเดียว
	//
	// ลบของเดิมทั้งหมดก่อนแล้วใส่ชุดใหม่ — ไม่ใช่การเพิ่มทับ
	SetRoles(ctx context.Context, userID uuid.UUID, roles []string, grantedBy uuid.UUID) error

	// CountSuperAdmins นับ SUPER_ADMIN ที่เหลือในระบบ
	//
	// ใช้กันไม่ให้ระบบเหลือ SUPER_ADMIN ศูนย์คน ซึ่งจะทำให้ไม่มีใคร
	// แก้ role ให้ใครได้อีกเลย และต้องไปแก้ในฐานข้อมูลด้วยมือ
	CountSuperAdmins(ctx context.Context) (int64, error)

	// GrantRole เพิ่ม role ให้ผู้ใช้แบบเรียกซ้ำได้
	//
	// คืน granted=false เมื่อผู้ใช้มี role นั้นอยู่แล้ว ซึ่งไม่ใช่ error
	GrantRole(ctx context.Context, userID uuid.UUID, roleCode string) (granted bool, err error)

	// FindBootstrapAdmin หารายการ bootstrap_admins จากอีเมล (ไม่สนตัวพิมพ์)
	//
	// คืน domain.ErrBootstrapAdminNotFound เมื่อไม่อยู่ในรายการ — กรณีปกติ
	//
	// 🔐 method นี้ตอบแค่ว่า "อีเมลนี้อยู่ในรายการไหม" เท่านั้น
	//    เงื่อนไขว่าต้องยืนยันอีเมลแล้วถึงจะ grant ได้ อยู่ที่ชั้น application
	//    (AuthService.reconcileBootstrapAdmin) ไม่ใช่ที่นี่ — จงใจให้คนอ่าน
	//    เห็นกฎความปลอดภัยข้อนั้นในชั้นที่ตัดสินใจ ไม่ใช่ซ่อนไว้ใน adapter
	FindBootstrapAdmin(ctx context.Context, email string) (domain.BootstrapAdmin, error)

	// IsBootstrapAdmin บอกว่าอีเมลนี้อยู่ในรายการ bootstrap_admins ไหม
	//
	// 🔐 เช่นเดียวกับ FindBootstrapAdmin — ไม่ตรวจ email_verified ให้
	IsBootstrapAdmin(ctx context.Context, email string) (bool, error)

	// MarkBootstrapAdminGranted บันทึกเวลาที่ grant สำเร็จ
	MarkBootstrapAdminGranted(ctx context.Context, email string) error
}
