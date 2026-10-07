// Package application รวม use case ของ auth-service
//
// ชั้นนี้พึ่งพาแต่ internal/port กับ internal/domain — ไม่มี Fiber, GORM,
// ไลบรารี JWT หรือ SDK ของ Google เลย
package application

import (
	"errors"
	"fmt"
)

// Sentinel error ที่ชั้น handler แปลงเป็นสถานะ HTTP
//
// ข้อความที่ตอบผู้เรียกอยู่ที่ชั้น handler ไม่ใช่ที่นี่ เพราะ error ตัวเดียวกัน
// ตอบข้อความต่างกันตาม endpoint — เช่น domain.ErrUserNotFound ตอบ
// "User not found" ที่ /me แต่ตอบ "ไม่พบผู้ใช้" ที่หน้า admin
var (
	// ErrMissingCredentials อีเมลหรือรหัสผ่านว่าง (เฉพาะ /signup — /login
	// ไม่ตรวจ ปล่อยให้หาไม่เจอแล้วตอบ 401 เหมือนรหัสผ่านผิด)
	ErrMissingCredentials = errors.New("ต้องมีทั้งอีเมลและรหัสผ่าน")

	// ErrHashPassword hash รหัสผ่านไม่สำเร็จ
	ErrHashPassword = errors.New("hash รหัสผ่านไม่สำเร็จ")

	// ErrEmailExists สร้างบัญชีไม่สำเร็จตอน /signup
	//
	// ⚠️ เป็นการ "ตีความ" error จาก repository ไม่ใช่การตรวจก่อนสร้าง
	//    repository คืน error ดิบมา แล้ว Signup ตีความว่าอีเมลซ้ำ (409)
	//    ส่วน GoogleLogin ตีความ error ตัวเดียวกันเป็น ErrCreateUser (500)
	ErrEmailExists = errors.New("อีเมลนี้มีบัญชีอยู่แล้ว")

	// ErrCreateUser สร้างบัญชีไม่สำเร็จตอน /google
	ErrCreateUser = errors.New("สร้างบัญชีไม่สำเร็จ")

	// ErrInvalidCredentials อีเมลไม่มีในระบบ หรือรหัสผ่านไม่ตรง
	//
	// รวมสองกรณีเป็นตัวเดียวโดยตั้งใจ เพื่อไม่ให้ผู้เรียกแยกได้ว่าอีเมลไหน
	// มีบัญชีอยู่ (พฤติกรรมเดิม)
	ErrInvalidCredentials = errors.New("อีเมลหรือรหัสผ่านไม่ถูกต้อง")

	// ErrPasswordLoginUnavailable บัญชีนี้ไม่มีรหัสผ่าน — สมัครผ่าน provider ภายนอก
	ErrPasswordLoginUnavailable = errors.New("บัญชีนี้ไม่ได้ตั้งรหัสผ่านไว้")

	// ErrIssueToken เซ็น token ไม่สำเร็จ
	//
	// 🔸 เดิม main.go ทิ้ง error นี้ (token, roles, _ := issueToken(user))
	//    ทั้งสามเส้นทาง แล้วตอบ 200/201 พร้อม token ว่าง
	//    ตอนนี้ส่งต่อให้ handler ตอบ 500 — เส้นทางสำเร็จไม่เปลี่ยน
	ErrIssueToken = errors.New("ออก token ไม่สำเร็จ")

	// ErrListUsers ดึงรายชื่อผู้ใช้ไม่สำเร็จ
	ErrListUsers = errors.New("ดึงรายชื่อผู้ใช้ไม่สำเร็จ")

	// ErrListRoles ดึงรายการ role ไม่สำเร็จ
	ErrListRoles = errors.New("ดึงรายการ role ไม่สำเร็จ")

	// ErrRoleCheck ตรวจสอบ role ที่มีอยู่จริงไม่สำเร็จ
	ErrRoleCheck = errors.New("ตรวจสอบ role ไม่สำเร็จ")

	// ErrSuperAdminCount นับ SUPER_ADMIN ที่เหลือไม่สำเร็จ
	ErrSuperAdminCount = errors.New("ตรวจสอบจำนวนผู้ดูแลไม่สำเร็จ")

	// ErrSaveRoles บันทึก role ไม่สำเร็จ
	ErrSaveRoles = errors.New("บันทึก role ไม่สำเร็จ")
)

// 🔒 สอง error นี้คือการป้องกันที่สำคัญที่สุดของทั้ง service
//
// ทั้งคู่กันไม่ให้ระบบเข้าสถานะที่แก้กลับเองไม่ได้ และต้องไปแก้ในฐานข้อมูล
// ด้วยมือ — ห้ามผ่อนเงื่อนไขทั้งสองข้อนี้โดยไม่มีทางแก้กลับที่ทดสอบแล้ว
var (
	// ErrCannotRemoveOwnSuperAdmin ผู้เรียกพยายามถอด SUPER_ADMIN ของตัวเอง
	ErrCannotRemoveOwnSuperAdmin = errors.New("ถอดสิทธิ์ SUPER_ADMIN ของตัวเองไม่ได้")

	// ErrLastSuperAdmin การเปลี่ยนนี้จะทำให้ระบบเหลือ SUPER_ADMIN ศูนย์คน
	ErrLastSuperAdmin = errors.New("ระบบจะเหลือ SUPER_ADMIN ศูนย์คน")
)

// UnknownRoleError คือ role code ที่ผู้เรียกส่งมาแต่ไม่มีอยู่ในตาราง roles
//
// เป็น type ไม่ใช่ sentinel เพราะข้อความที่ตอบต้องมีชื่อ role ที่ผิดอยู่ด้วย
type UnknownRoleError struct {
	Code string
}

func (e UnknownRoleError) Error() string {
	return fmt.Sprintf("ไม่รู้จัก role %s", e.Code)
}
