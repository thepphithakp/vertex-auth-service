package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// requireRole ตรวจ role จาก token
//
// ⚠️ มีทางผ่านสำรองสำหรับช่วงเปลี่ยนผ่าน: บัญชีที่อยู่ใน bootstrap_admins
//
//	และยืนยันอีเมลแล้ว จะผ่านได้แม้ token ใบเดิมยังไม่มี roles claim
//
//	จำเป็นเพราะ token มีอายุ 72 ชั่วโมง ถ้าไม่มีทางนี้ ผู้ดูแลระบบจะเข้า
//	หน้า admin ไม่ได้จนกว่า token เดิมจะหมดอายุ — ล็อกตัวเองออกจากระบบ
//
//	ทางผ่านนี้ปลอดภัยเพราะ bootstrap_admins แก้ได้ผ่าน migration เท่านั้น
//	และยังบังคับ email_verified เหมือนกัน
func requireRole(want string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if roles, ok := c.Locals("roles").([]string); ok && hasRole(roles, want) {
			return c.Next()
		}

		if want == RoleSuperAdmin && isBootstrapAdminFromToken(c) {
			return c.Next()
		}
		return sendError(c, 403, "ไม่มีสิทธิ์เข้าถึงส่วนนี้")
	}
}

func isBootstrapAdminFromToken(c *fiber.Ctx) bool {
	userIDStr, _ := c.Locals("userId").(string)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}

	var user User
	if err := dbConn.First(&user, "id = ?", userID).Error; err != nil {
		return false
	}
	if !user.EmailVerified {
		return false
	}

	var n int64
	dbConn.Model(&BootstrapAdmin{}).
		Where("lower(email) = lower(?)", user.Email).
		Count(&n)
	return n > 0
}

type userWithRoles struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	FullName      string    `json:"fullName"`
	EmailVerified bool      `json:"emailVerified"`
	Roles         []string  `json:"roles"`
}

// handleListRoles คืนรายการ role ทั้งหมดให้ backoffice เอาไปทำ dropdown
func handleListRoles(c *fiber.Ctx) error {
	var roles []Role
	if err := dbConn.Order("code").Find(&roles).Error; err != nil {
		return sendError(c, 500, "ดึงรายการ role ไม่สำเร็จ")
	}
	return c.JSON(roles)
}

// handleAdminListUsers คืนผู้ใช้พร้อม role
func handleAdminListUsers(c *fiber.Ctx) error {
	var users []User
	q := dbConn.Order("created_at desc")
	if search := c.Query("q"); search != "" {
		like := "%" + search + "%"
		q = q.Where("email ILIKE ? OR full_name ILIKE ?", like, like)
	}
	if err := q.Limit(200).Find(&users).Error; err != nil {
		return sendError(c, 500, "ดึงรายชื่อผู้ใช้ไม่สำเร็จ")
	}

	out := make([]userWithRoles, 0, len(users))
	for _, u := range users {
		out = append(out, userWithRoles{
			ID: u.ID, Email: u.Email, FullName: u.FullName,
			EmailVerified: u.EmailVerified,
			Roles:         rolesForUser(dbConn, u.ID),
		})
	}
	return c.JSON(out)
}

type updateRolesRequest struct {
	Roles []string `json:"roles"`
}

// handleAdminUpdateRoles ตั้ง role ของผู้ใช้คนหนึ่ง
func handleAdminUpdateRoles(c *fiber.Ctx) error {
	targetID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return sendError(c, 400, "user id ไม่ถูกต้อง")
	}

	actorID, _ := uuid.Parse(c.Locals("userId").(string))

	var req updateRolesRequest
	if err := c.BodyParser(&req); err != nil {
		return sendError(c, 400, "request body ไม่ถูกต้อง")
	}

	// role ที่ส่งมาต้องมีอยู่จริงทุกตัว
	valid := map[string]bool{}
	var all []Role
	if err := dbConn.Find(&all).Error; err != nil {
		return sendError(c, 500, "ตรวจสอบ role ไม่สำเร็จ")
	}
	for _, r := range all {
		valid[r.Code] = true
	}
	cleaned := make([]string, 0, len(req.Roles))
	seen := map[string]bool{}
	for _, r := range req.Roles {
		if !valid[r] {
			return sendError(c, 400, "ไม่รู้จัก role "+r)
		}
		if !seen[r] {
			seen[r] = true
			cleaned = append(cleaned, r)
		}
	}
	// ทุกคนต้องมี USER เป็นพื้นฐานเสมอ
	if !seen[RoleUser] {
		cleaned = append(cleaned, RoleUser)
	}

	var target User
	if err := dbConn.First(&target, "id = ?", targetID).Error; err != nil {
		return sendError(c, 404, "ไม่พบผู้ใช้")
	}

	losingSuperAdmin := hasRole(rolesForUser(dbConn, targetID), RoleSuperAdmin) && !seen[RoleSuperAdmin]

	// 🔒 ห้ามถอด SUPER_ADMIN ของตัวเอง — กันล็อกตัวเองออกโดยไม่ตั้งใจ
	if losingSuperAdmin && targetID == actorID {
		return sendError(c, 400, "ถอดสิทธิ์ SUPER_ADMIN ของตัวเองไม่ได้ ให้ผู้ดูแลคนอื่นทำแทน")
	}

	// 🔒 ห้ามให้ระบบเหลือ SUPER_ADMIN ศูนย์คน
	if losingSuperAdmin {
		n, err := countSuperAdmins(dbConn)
		if err != nil {
			return sendError(c, 500, "ตรวจสอบจำนวนผู้ดูแลไม่สำเร็จ")
		}
		if n <= 1 {
			return sendError(c, 400, "ระบบต้องมี SUPER_ADMIN อย่างน้อยหนึ่งคน")
		}
	}

	err = dbConn.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`DELETE FROM user_roles WHERE user_id = ?`, targetID).Error; err != nil {
			return err
		}
		for _, r := range cleaned {
			if err := tx.Exec(`
				INSERT INTO user_roles (user_id, role_code, granted_by)
				VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, targetID, r, actorID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return sendError(c, 500, "บันทึก role ไม่สำเร็จ")
	}

	log.Printf("🔐 %s เปลี่ยน role ของ %s เป็น %v", actorID, target.Email, cleaned)

	return c.JSON(userWithRoles{
		ID: target.ID, Email: target.Email, FullName: target.FullName,
		EmailVerified: target.EmailVerified,
		Roles:         rolesForUser(dbConn, targetID),
	})
}
