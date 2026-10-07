package handler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

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
type Middleware struct {
	tokens port.TokenService
	users  port.UserRepository
	roles  port.RoleRepository
}

func NewMiddleware(
	tokens port.TokenService, users port.UserRepository, roles port.RoleRepository,
) *Middleware {
	return &Middleware{tokens: tokens, users: users, roles: roles}
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

// isBootstrapAdminFromToken คือทางผ่านสำรองของ RequireRole
//
// 🔐 บังคับ email_verified เหมือน reconcileBootstrapAdmin — ถ้าไม่บังคับ
//
//	คนที่รู้ว่าอีเมลไหนอยู่ในรายการจะสมัครด้วยอีเมลนั้นก่อนเจ้าตัว
//	แล้วเข้าหน้า admin ได้ทันที
//
// error ทุกชนิดถือว่า "ไม่ผ่าน" เหมือนเดิม — ทางผ่านสำรองต้องไม่เปิดกว้างขึ้น
// เพราะอ่านฐานข้อมูลไม่สำเร็จ
func (m *Middleware) isBootstrapAdminFromToken(c *fiber.Ctx) bool {
	userIDStr, _ := c.Locals(localsUserID).(string)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}

	user, err := m.users.FindByID(c.UserContext(), userID)
	if err != nil {
		return false
	}
	if !user.EmailVerified {
		return false
	}

	isBootstrap, err := m.roles.IsBootstrapAdmin(c.UserContext(), user.Email)
	if err != nil {
		return false
	}
	return isBootstrap
}
