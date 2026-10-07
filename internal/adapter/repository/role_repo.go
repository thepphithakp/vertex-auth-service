package repository

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/domain"
)

// GORMRoleRepository implements port.RoleRepository
type GORMRoleRepository struct {
	db *gorm.DB
}

func NewGORMRoleRepository(db *gorm.DB) *GORMRoleRepository {
	return &GORMRoleRepository{db: db}
}

// RolesForUser อ่าน role ทั้งหมดของผู้ใช้
//
// คืน [USER] เมื่อไม่มีแถวเลย เพื่อให้ token มี roles เสมอ
// ทำให้ service ปลายทางไม่ต้องเดาความหมายของ "ไม่มี roles"
func (r *GORMRoleRepository) RolesForUser(ctx context.Context, userID uuid.UUID) []string {
	var roles []string
	if err := r.db.WithContext(ctx).Model(&model.UserRole{}).
		Where("user_id = ?", userID).
		Order("role_code").
		Pluck("role_code", &roles).Error; err != nil {
		log.Printf("อ่าน role ของ %s ไม่สำเร็จ: %v", userID, err)
		return []string{domain.RoleUser}
	}
	if len(roles) == 0 {
		return []string{domain.RoleUser}
	}
	return roles
}

// EnsureDefaultRole ให้ role USER กับบัญชีที่เพิ่งสร้าง
func (r *GORMRoleRepository) EnsureDefaultRole(ctx context.Context, userID uuid.UUID) {
	if err := r.db.WithContext(ctx).Exec(`
		INSERT INTO user_roles (user_id, role_code)
		VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, domain.RoleUser).Error; err != nil {
		log.Printf("ให้ role USER กับ %s ไม่สำเร็จ: %v", userID, err)
	}
}

func (r *GORMRoleRepository) ListRoles(ctx context.Context) ([]domain.Role, error) {
	var rows []model.Role
	if err := r.db.WithContext(ctx).Order("code").Find(&rows).Error; err != nil {
		return nil, err
	}
	roles := make([]domain.Role, len(rows))
	for i := range rows {
		roles[i] = rows[i].ToDomain()
	}
	return roles, nil
}

func (r *GORMRoleRepository) ValidRoleCodes(ctx context.Context) (map[string]bool, error) {
	var rows []model.Role
	if err := r.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	valid := make(map[string]bool, len(rows))
	for _, row := range rows {
		valid[row.Code] = true
	}
	return valid, nil
}

// SetRoles แทนที่ role ทั้งชุดในทรานแซกชันเดียว
//
// ลบทั้งหมดแล้วใส่ใหม่ ไม่ใช่การเพิ่มทับ — ถ้าล้มกลางทางจะ rollback
// ทำให้ไม่มีสถานะ "ลบแล้วแต่ยังไม่ได้ใส่" ที่ผู้ใช้จะไม่เหลือ role เลย
func (r *GORMRoleRepository) SetRoles(
	ctx context.Context, userID uuid.UUID, roles []string, grantedBy uuid.UUID,
) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`DELETE FROM user_roles WHERE user_id = ?`, userID).Error; err != nil {
			return err
		}
		for _, role := range roles {
			if err := tx.Exec(`
				INSERT INTO user_roles (user_id, role_code, granted_by)
				VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, userID, role, grantedBy).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *GORMRoleRepository) CountSuperAdmins(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.UserRole{}).
		Where("role_code = ?", domain.RoleSuperAdmin).
		Count(&n).Error
	return n, err
}

func (r *GORMRoleRepository) GrantRole(
	ctx context.Context, userID uuid.UUID, roleCode string,
) (bool, error) {
	res := r.db.WithContext(ctx).Exec(`
		INSERT INTO user_roles (user_id, role_code)
		VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, roleCode)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (r *GORMRoleRepository) FindBootstrapAdmin(
	ctx context.Context, email string,
) (domain.BootstrapAdmin, error) {
	var row model.BootstrapAdmin
	err := r.db.WithContext(ctx).
		Where("lower(email) = ?", strings.ToLower(email)).
		First(&row).Error
	if err != nil {
		return domain.BootstrapAdmin{}, domain.ErrBootstrapAdminNotFound
	}
	return row.ToDomain(), nil
}

func (r *GORMRoleRepository) IsBootstrapAdmin(ctx context.Context, email string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&model.BootstrapAdmin{}).
		Where("lower(email) = lower(?)", email).
		Count(&n).Error
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *GORMRoleRepository) MarkBootstrapAdminGranted(ctx context.Context, email string) error {
	return r.db.WithContext(ctx).Model(&model.BootstrapAdmin{}).
		Where("email = ?", email).
		Update("granted_at", time.Now()).Error
}
