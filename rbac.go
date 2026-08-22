package main

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role code ที่โค้ดอ้างถึงโดยตรง — ต้องตรงกับ db/codeowned/R__0010_roles.sql
const (
	RoleSuperAdmin = "SUPER_ADMIN"
	RolePetAdmin   = "PET_ADMIN"
	RoleUser       = "USER"
)

type Role struct {
	Code        string `gorm:"primaryKey" json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSystem    bool   `json:"isSystem"`
}

func (Role) TableName() string { return "roles" }

type UserRole struct {
	UserID    uuid.UUID `gorm:"primaryKey;type:uuid"`
	RoleCode  string    `gorm:"primaryKey;type:varchar(50)"`
	GrantedAt time.Time
	GrantedBy *uuid.UUID `gorm:"type:uuid"`
}

func (UserRole) TableName() string { return "user_roles" }

type BootstrapAdmin struct {
	Email     string `gorm:"primaryKey"`
	RoleCode  string
	Note      string
	GrantedAt *time.Time
}

func (BootstrapAdmin) TableName() string { return "bootstrap_admins" }

// rolesForUser อ่าน role ทั้งหมดของผู้ใช้
//
// คืน [USER] เมื่อไม่มีแถวเลย เพื่อให้ token มี roles เสมอ
// ทำให้ service ปลายทางไม่ต้องเดาความหมายของ "ไม่มี roles"
func rolesForUser(db *gorm.DB, userID uuid.UUID) []string {
	var roles []string
	if err := db.Model(&UserRole{}).
		Where("user_id = ?", userID).
		Order("role_code").
		Pluck("role_code", &roles).Error; err != nil {
		log.Printf("อ่าน role ของ %s ไม่สำเร็จ: %v", userID, err)
		return []string{RoleUser}
	}
	if len(roles) == 0 {
		return []string{RoleUser}
	}
	return roles
}

// reconcileBootstrapAdmin ให้ role กับบัญชีที่อยู่ในรายการ bootstrap_admins
//
// 🔐 กฎความปลอดภัยที่ห้ามละเมิด: grant ได้เฉพาะบัญชีที่ยืนยันอีเมลแล้วเท่านั้น
//
// เหตุผล: handleSignup สมัครด้วย password ได้โดยไม่ยืนยันอีเมล
// ถ้าไม่มีเงื่อนไขนี้ ใครก็ได้ที่รู้ว่าอีเมลไหนอยู่ในรายการ สามารถสมัครบัญชี
// ด้วยอีเมลนั้นก่อนเจ้าตัว แล้วได้ SUPER_ADMIN ไปทันที
//
// เรียกหลัง login/signup สำเร็จทุกครั้ง เพื่อให้บัญชีที่เพิ่งยืนยันอีเมล
// ได้สิทธิ์โดยไม่ต้องรัน migration ซ้ำ
func reconcileBootstrapAdmin(db *gorm.DB, user User) {
	if !user.EmailVerified {
		return
	}

	var entry BootstrapAdmin
	err := db.Where("lower(email) = ?", strings.ToLower(user.Email)).First(&entry).Error
	if err != nil {
		return // ไม่ได้อยู่ในรายการ — กรณีปกติ
	}

	res := db.Exec(`
		INSERT INTO user_roles (user_id, role_code)
		VALUES (?, ?) ON CONFLICT DO NOTHING`, user.ID, entry.RoleCode)
	if res.Error != nil {
		log.Printf("grant %s ให้ %s ไม่สำเร็จ: %v", entry.RoleCode, user.Email, res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("🔐 grant %s ให้ %s (จาก bootstrap_admins)", entry.RoleCode, user.Email)
		db.Model(&BootstrapAdmin{}).
			Where("email = ?", entry.Email).
			Update("granted_at", time.Now())
	}
}

// ensureDefaultRole ให้ role USER กับบัญชีที่เพิ่งสร้าง
func ensureDefaultRole(db *gorm.DB, userID uuid.UUID) {
	if err := db.Exec(`
		INSERT INTO user_roles (user_id, role_code)
		VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, RoleUser).Error; err != nil {
		log.Printf("ให้ role USER กับ %s ไม่สำเร็จ: %v", userID, err)
	}
}

// hasRole ใช้ในชั้น HTTP
func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// countSuperAdmins นับ SUPER_ADMIN ที่เหลือในระบบ
//
// ใช้กันไม่ให้ระบบเหลือ SUPER_ADMIN ศูนย์คน ซึ่งจะทำให้ไม่มีใคร
// แก้ role ให้ใครได้อีกเลย และต้องไปแก้ในฐานข้อมูลด้วยมือ
func countSuperAdmins(db *gorm.DB) (int64, error) {
	var n int64
	err := db.Model(&UserRole{}).Where("role_code = ?", RoleSuperAdmin).Count(&n).Error
	return n, err
}

// rolesFromClaims อ่าน roles จาก token
//
// token ที่ออกก่อนเฟสนี้ยังไม่มี claim นี้ — ถือเป็น USER
// ทำให้ผู้ใช้เดิมที่ถือ token อายุ 72 ชั่วโมงอยู่ ใช้งานต่อได้ตามปกติ
func rolesFromClaims(claims map[string]interface{}) []string {
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

// requiredSchemaVersion คือเวอร์ชัน migration ต่ำสุดที่โค้ดชุดนี้ทำงานได้
//
// ⚠️ ต้องเพิ่มค่านี้ทุกครั้งที่เพิ่ม V__ ใหม่ที่โค้ดพึ่งพา
// และห้ามเพิ่มถ้าโค้ดยังไม่ได้ใช้ schema นั้น (จะทำให้ deploy ไม่ผ่านโดยไม่จำเป็น)
const requiredSchemaVersion = 3

// assertSchemaReady มาแทน AutoMigrate
//
// Flyway Job รันก่อน pod ใหม่ขึ้น หน้าที่ของแอปเหลือแค่ยืนยันว่า migration
// รันครบแล้ว แล้วล้มทันทีถ้ายัง — ปลอดภัยกว่าปล่อยให้ขึ้นแล้วไปพังตอน login แรก
func assertSchemaReady() {
	var version string
	err := dbConn.Raw(`
		SELECT version FROM flyway_schema_history
		WHERE success AND version IS NOT NULL
		ORDER BY installed_rank DESC LIMIT 1`).Scan(&version).Error
	if err != nil {
		log.Fatalf("อ่านตาราง flyway_schema_history ไม่ได้ — migration อาจยังไม่เคยรัน "+
			"(ตรวจ search_path และ Flyway Job): %v", err)
	}
	major, convErr := strconv.Atoi(strings.SplitN(strings.TrimSpace(version), ".", 2)[0])
	if convErr != nil {
		log.Fatalf("อ่าน schema version %q ไม่ได้: %v", version, convErr)
	}
	if major < requiredSchemaVersion {
		log.Fatalf("ฐานข้อมูลอยู่ที่ V%s แต่โค้ดต้องการ V%d — รัน migration ก่อน",
			version, requiredSchemaVersion)
	}
	log.Printf("schema version V%s (ต้องการอย่างน้อย V%d) ✓", version, requiredSchemaVersion)

	required := []string{"roles", "user_roles", "bootstrap_admins"}
	for _, table := range required {
		if !dbConn.Migrator().HasTable(table) {
			log.Fatalf("ไม่พบตาราง %q — ยังไม่ได้รัน Flyway migration (ดู db/migration)", table)
		}
	}
	if !dbConn.Migrator().HasColumn(&User{}, "email_verified") {
		log.Fatal("users ไม่มี column email_verified — ยังไม่ได้รัน Flyway migration")
	}

	n, err := countSuperAdmins(dbConn)
	if err != nil {
		log.Printf("นับ SUPER_ADMIN ไม่สำเร็จ: %v", err)
		return
	}
	if n == 0 {
		log.Println("⚠️  ยังไม่มี SUPER_ADMIN ในระบบ — backoffice จะเข้าหน้า admin ไม่ได้")
		log.Println("    ให้บัญชีที่อยู่ใน bootstrap_admins login ผ่าน Google หนึ่งครั้ง")
	} else {
		log.Printf("🔐 SUPER_ADMIN ในระบบ: %d คน", n)
	}
}

// markEmailVerified ตั้ง email_verified = true เมื่อยืนยันผ่าน provider ที่เชื่อถือได้
//
// เขียนลงฐานข้อมูลเฉพาะตอนที่ค่ายังไม่เป็น true เพื่อไม่ให้ยิง UPDATE ทุกครั้งที่ login
func markEmailVerified(user *User) {
	if user.EmailVerified {
		return
	}
	if err := dbConn.Model(&User{}).
		Where("id = ?", user.ID).
		Update("email_verified", true).Error; err != nil {
		log.Printf("ตั้ง email_verified ให้ %s ไม่สำเร็จ: %v", user.Email, err)
		return
	}
	user.EmailVerified = true
}
