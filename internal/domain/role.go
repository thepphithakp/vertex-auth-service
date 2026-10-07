package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role code ที่โค้ดอ้างถึงโดยตรง — ต้องตรงกับ db/codeowned/R__0010_roles.sql
const (
	RoleSuperAdmin = "SUPER_ADMIN"
	RolePetAdmin   = "PET_ADMIN"
	RoleUser       = "USER"
)

// Role คือ role หนึ่งตัวในระบบ — backoffice เอาไปทำ dropdown
type Role struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSystem    bool   `json:"isSystem"`
}

// UserRole ผูกผู้ใช้กับ role หนึ่งตัว
type UserRole struct {
	UserID    uuid.UUID
	RoleCode  string
	GrantedAt time.Time
	GrantedBy *uuid.UUID
}

// BootstrapAdmin คือรายการอีเมลที่จะได้ role ทันทีเมื่อยืนยันอีเมลแล้ว
//
// แก้ได้ผ่าน migration เท่านั้น ซึ่งเป็นเหตุผลที่ทางผ่านสำรองใน requireRole
// เชื่อถือรายการนี้ได้
type BootstrapAdmin struct {
	Email     string
	RoleCode  string
	Note      string
	GrantedAt *time.Time
}

// HasRole บอกว่า role ที่ต้องการอยู่ในรายการไหม
func HasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// RolesFromClaims อ่าน roles จาก token
//
// token ที่ออกก่อนเฟสนี้ยังไม่มี claim นี้ — ถือเป็น USER
// ทำให้ผู้ใช้เดิมที่ถือ token อายุ 72 ชั่วโมงอยู่ ใช้งานต่อได้ตามปกติ
func RolesFromClaims(claims map[string]interface{}) []string {
	raw, ok := claims["roles"].([]interface{})
	if !ok {
		return []string{RoleUser}
	}
	roles := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok && s != "" {
			roles = append(roles, s)
		}
	}
	if len(roles) == 0 {
		return []string{RoleUser}
	}
	return roles
}
