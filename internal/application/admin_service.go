package application

import (
	"context"
	"log"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// adminUserListLimit จำกัดจำนวนผู้ใช้ที่หน้า admin ดึงได้ในครั้งเดียว
const adminUserListLimit = 200

// UserWithRoles คือผู้ใช้หนึ่งคนพร้อม role ปัจจุบัน
//
// ไม่มี json tag — รูปแบบ response เป็นเรื่องของชั้น handler
type UserWithRoles struct {
	User  domain.User
	Roles []string
}

// AdminService คือ use case ของหน้า admin ที่ backoffice เรียก
type AdminService struct {
	users port.UserRepository
	roles port.RoleRepository
}

func NewAdminService(users port.UserRepository, roles port.RoleRepository) *AdminService {
	return &AdminService{users: users, roles: roles}
}

// ListRoles คืนรายการ role ทั้งหมดให้ backoffice เอาไปทำ dropdown
func (s *AdminService) ListRoles(ctx context.Context) ([]domain.Role, error) {
	roles, err := s.roles.ListRoles(ctx)
	if err != nil {
		return nil, ErrListRoles
	}
	return roles, nil
}

// ListUsers คืนผู้ใช้พร้อม role กรองด้วย search ได้ (search ว่าง = ไม่กรอง)
func (s *AdminService) ListUsers(ctx context.Context, search string) ([]UserWithRoles, error) {
	users, err := s.users.List(ctx, search, adminUserListLimit)
	if err != nil {
		return nil, ErrListUsers
	}

	out := make([]UserWithRoles, 0, len(users))
	for _, u := range users {
		out = append(out, UserWithRoles{
			User:  u,
			Roles: s.roles.RolesForUser(ctx, u.ID),
		})
	}
	return out, nil
}

// UpdateRoles ตั้ง role ของผู้ใช้คนหนึ่งใหม่ทั้งชุด
//
// 🔒 ลำดับของการตรวจสำคัญและห้ามสลับ:
//
//	 1. role ที่ส่งมาต้องมีอยู่จริงทุกตัว (ตรวจก่อนหาผู้ใช้ — role ผิด
//	    บวกผู้ใช้ไม่มีจริง ตอบ "ไม่รู้จัก role" ไม่ใช่ "ไม่พบผู้ใช้")
//	 2. บังคับใส่ USER เสมอ
//	 3. ผู้ใช้เป้าหมายต้องมีจริง
//	 4. ห้ามถอด SUPER_ADMIN ของตัวเอง
//	 5. ห้ามให้ระบบเหลือ SUPER_ADMIN ศูนย์คน
//
//	ข้อ 4 กับ 5 เป็นการป้องกันที่สำคัญที่สุดของทั้ง service — ทั้งคู่กันไม่ให้
//	ระบบเข้าสถานะที่ไม่มีใครแก้ role ให้ใครได้อีกเลย และต้องไปแก้ใน
//	ฐานข้อมูลด้วยมือ ข้อ 4 ต้องมาก่อนข้อ 5 เพื่อให้ผู้เรียกที่ลดสิทธิ์ตัวเอง
//	ได้ข้อความที่บอกวิธีแก้ (ให้ผู้ดูแลคนอื่นทำแทน) ไม่ใช่ข้อความเรื่องจำนวน
func (s *AdminService) UpdateRoles(
	ctx context.Context, targetID, actorID uuid.UUID, requested []string,
) (UserWithRoles, error) {
	// 1. role ที่ส่งมาต้องมีอยู่จริงทุกตัว
	valid, err := s.roles.ValidRoleCodes(ctx)
	if err != nil {
		return UserWithRoles{}, ErrRoleCheck
	}

	cleaned := make([]string, 0, len(requested))
	seen := map[string]bool{}
	for _, r := range requested {
		if !valid[r] {
			return UserWithRoles{}, UnknownRoleError{Code: r}
		}
		if !seen[r] {
			seen[r] = true
			cleaned = append(cleaned, r)
		}
	}

	// 2. ทุกคนต้องมี USER เป็นพื้นฐานเสมอ
	if !seen[domain.RoleUser] {
		cleaned = append(cleaned, domain.RoleUser)
	}

	// 3. ผู้ใช้เป้าหมายต้องมีจริง
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return UserWithRoles{}, err // domain.ErrUserNotFound
	}

	losingSuperAdmin := domain.HasRole(s.roles.RolesForUser(ctx, targetID), domain.RoleSuperAdmin) &&
		!seen[domain.RoleSuperAdmin]

	// 4. 🔒 ห้ามถอด SUPER_ADMIN ของตัวเอง — กันล็อกตัวเองออกโดยไม่ตั้งใจ
	if losingSuperAdmin && targetID == actorID {
		return UserWithRoles{}, ErrCannotRemoveOwnSuperAdmin
	}

	// 5. 🔒 ห้ามให้ระบบเหลือ SUPER_ADMIN ศูนย์คน
	if losingSuperAdmin {
		n, err := s.roles.CountSuperAdmins(ctx)
		if err != nil {
			return UserWithRoles{}, ErrSuperAdminCount
		}
		if n <= 1 {
			return UserWithRoles{}, ErrLastSuperAdmin
		}
	}

	if err := s.roles.SetRoles(ctx, targetID, cleaned, actorID); err != nil {
		return UserWithRoles{}, ErrSaveRoles
	}

	log.Printf("🔐 %s เปลี่ยน role ของ %s เป็น %v", actorID, target.Email, cleaned)

	return UserWithRoles{
		User:  target,
		Roles: s.roles.RolesForUser(ctx, targetID),
	}, nil
}
