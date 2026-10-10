package handler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"vertex-auth-service/internal/application"
	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// Key ที่ RequireAuth เขียนลง c.Locals ให้ handler ปลายทางอ่าน
const (
	localsUserID = "userId"
	localsRoles  = "roles"
)

// Middleware รวม middleware ที่ต้องใช้ dependency
//
// เดิมอ่านตัวแปร global (dbConn, acceptedPublicKeys) ตอนนี้รับ port
// เข้ามาตอนประกอบที่ internal/bootstrap แทน
//
// 🔴 ต่อกับ *application.AuthService ตรงๆ (เหมือน AuthHandler) ไม่ถือ
// port.UserRepository/RoleRepository เองอีกต่อไป — ทางผ่านสำรองของ
// RequireRole เป็น business rule ที่ย้ายไปอยู่
// AuthService.IsBootstrapAdminFallback แล้ว middleware แค่เรียกใช้
// (เดิมเคยเรียก FindByID + IsBootstrapAdmin ตรงๆ ที่นี่ ซึ่งเป็น business
// logic ที่ไม่ควรอยู่ใน adapter)
type Middleware struct {
	tokens port.TokenService
	auth   *application.AuthService
}

func NewMiddleware(tokens port.TokenService, auth *application.AuthService) *Middleware {
	return &Middleware{tokens: tokens, auth: auth}
}

// RequireAuth ตรวจลายเซ็นและอายุ token แล้วใส่ userId กับ roles ลง context
func (m *Middleware) RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString, ok := bearerToken(c)
		if !ok {
			return SendError(c, 401, "Missing or invalid token")
		}

		claims, err := m.tokens.Verify(tokenString)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrTokenClaims):
				return SendError(c, 401, "Invalid token claims")
			case errors.Is(err, domain.ErrTokenSubject):
				return SendError(c, 401, "Invalid token subject")
			default:
				return SendError(c, 401, "Invalid or expired token")
			}
		}

		c.Locals(localsUserID, claims.UserID)
		c.Locals(localsRoles, claims.Roles)
		return c.Next()
	}
}

// RequireRole ตรวจ role จาก token
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
func (m *Middleware) RequireRole(want string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if roles, ok := c.Locals(localsRoles).([]string); ok && domain.HasRole(roles, want) {
			return c.Next()
		}

		if want == domain.RoleSuperAdmin && m.isBootstrapAdminFromToken(c) {
			return c.Next()
		}
		return SendError(c, 403, "ไม่มีสิทธิ์เข้าถึงส่วนนี้")
	}
}

// isBootstrapAdminFromToken แค่แปลง userId จาก context ให้เป็น uuid แล้ว
// ส่งต่อให้ AuthService.IsBootstrapAdminFallback ตัดสิน — ตัวนี้เป็น adapter
// concern (อ่านค่าจาก Fiber locals) ไม่ใช่ business rule เลย
func (m *Middleware) isBootstrapAdminFromToken(c *fiber.Ctx) bool {
	userIDStr, _ := c.Locals(localsUserID).(string)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}
	return m.auth.IsBootstrapAdminFallback(c.UserContext(), userID)
}
