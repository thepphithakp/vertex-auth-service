package handler

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"vertex-auth-service/internal/application"
	"vertex-auth-service/internal/domain"
)

// UpdateRolesRequest คือ body ของ PUT /admin/users/:id/roles
type UpdateRolesRequest struct {
	Roles []string `json:"roles"`
}

// userWithRolesResponse คือรูปแบบ response ของหน้า admin
type userWithRolesResponse struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	FullName      string    `json:"fullName"`
	EmailVerified bool      `json:"emailVerified"`
	Roles         []string  `json:"roles"`
}

func newUserWithRolesResponse(u application.UserWithRoles) userWithRolesResponse {
	return userWithRolesResponse{
		ID:            u.User.ID,
		Email:         u.User.Email,
		FullName:      u.User.FullName,
		EmailVerified: u.User.EmailVerified,
		Roles:         u.Roles,
	}
}

// AdminHandler รับ request ของหน้า admin ที่ backoffice เรียก
type AdminHandler struct {
	admin *application.AdminService
}

func NewAdminHandler(admin *application.AdminService) *AdminHandler {
	return &AdminHandler{admin: admin}
}

// ListRoles คืนรายการ role ทั้งหมดให้ backoffice เอาไปทำ dropdown
func (h *AdminHandler) ListRoles(c *fiber.Ctx) error {
	roles, err := h.admin.ListRoles(c.UserContext())
	if err != nil {
		return SendError(c, 500, "ดึงรายการ role ไม่สำเร็จ")
	}
	return c.JSON(roles)
}

// ListUsers คืนผู้ใช้พร้อม role กรองด้วย query ?q= ได้
func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	users, err := h.admin.ListUsers(c.UserContext(), c.Query("q"))
	if err != nil {
		return SendError(c, 500, "ดึงรายชื่อผู้ใช้ไม่สำเร็จ")
	}

	out := make([]userWithRolesResponse, 0, len(users))
	for _, u := range users {
		out = append(out, newUserWithRolesResponse(u))
	}
	return c.JSON(out)
}

// UpdateRoles ตั้ง role ของผู้ใช้คนหนึ่ง
func (h *AdminHandler) UpdateRoles(c *fiber.Ctx) error {
	targetID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return SendError(c, 400, "user id ไม่ถูกต้อง")
	}

	// ⚠️ ห้ามกลืน error ตรงนี้
	//
	// actorID ถูกใช้ในเช็คกันลดสิทธิ์ตัวเองที่ชั้น application
	// (targetID == actorID) ถ้า parse ไม่ได้แล้วปล่อยผ่าน actorID จะเป็น
	// uuid.Nil ซึ่งไม่มีวันตรงกับ targetID ของใครเลย → SUPER_ADMIN ถอด
	// SUPER_ADMIN ของตัวเองได้ และอาจไม่เหลือใครที่แก้กลับได้
	actorID, err := actorIDFrom(c)
	if err != nil {
		return SendError(c, 401, "ระบุตัวตนผู้เรียกไม่ได้")
	}

	var req UpdateRolesRequest
	if err := c.BodyParser(&req); err != nil {
		return SendError(c, 400, "request body ไม่ถูกต้อง")
	}

	updated, err := h.admin.UpdateRoles(c.UserContext(), targetID, actorID, req.Roles)
	if err != nil {
		var unknownRole application.UnknownRoleError
		switch {
		case errors.As(err, &unknownRole):
			return SendError(c, 400, "ไม่รู้จัก role "+unknownRole.Code)
		case errors.Is(err, application.ErrRoleCheck):
			return SendError(c, 500, "ตรวจสอบ role ไม่สำเร็จ")
		case errors.Is(err, domain.ErrUserNotFound):
			return SendError(c, 404, "ไม่พบผู้ใช้")
		case errors.Is(err, application.ErrCannotRemoveOwnSuperAdmin):
			return SendError(c, 400, "ถอดสิทธิ์ SUPER_ADMIN ของตัวเองไม่ได้ ให้ผู้ดูแลคนอื่นทำแทน")
		case errors.Is(err, application.ErrSuperAdminCount):
			return SendError(c, 500, "ตรวจสอบจำนวนผู้ดูแลไม่สำเร็จ")
		case errors.Is(err, application.ErrLastSuperAdmin):
			return SendError(c, 400, "ระบบต้องมี SUPER_ADMIN อย่างน้อยหนึ่งคน")
		default:
			return SendError(c, 500, "บันทึก role ไม่สำเร็จ")
		}
	}

	return c.JSON(newUserWithRolesResponse(updated))
}

// actorIDFrom ดึง user id ของผู้เรียกจาก context ที่ RequireAuth ใส่ไว้
//
// แยกออกมาเพื่อไม่ให้ต้องเขียน type assertion แบบไม่เช็คซ้ำหลายที่
// (assertion ที่ไม่เช็คจะ panic ทั้ง process ถ้า middleware เปลี่ยนรูปแบบค่า)
func actorIDFrom(c *fiber.Ctx) (uuid.UUID, error) {
	raw, ok := c.Locals(localsUserID).(string)
	if !ok || raw == "" {
		return uuid.Nil, fmt.Errorf("ไม่มี userId ใน context")
	}
	return uuid.Parse(raw)
}

// RegisterRoutes ผูก route ของ /api/v1/auth/admin
//
// ผู้เรียกต้องส่ง group ที่ผ่าน RequireAuth + RequireRole(SUPER_ADMIN) มาแล้ว
func (h *AdminHandler) RegisterRoutes(admin fiber.Router) {
	admin.Get("/users", h.ListUsers)
	admin.Put("/users/:id/roles", h.UpdateRoles)
	admin.Get("/roles", h.ListRoles)
}
