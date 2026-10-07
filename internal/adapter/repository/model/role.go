package model

import (
	"time"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
)

type Role struct {
	Code        string `gorm:"primaryKey"`
	Name        string
	Description string
	IsSystem    bool
}

func (Role) TableName() string { return "roles" }

func (m *Role) ToDomain() domain.Role {
	return domain.Role{
		Code:        m.Code,
		Name:        m.Name,
		Description: m.Description,
		IsSystem:    m.IsSystem,
	}
}

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

func (m *BootstrapAdmin) ToDomain() domain.BootstrapAdmin {
	return domain.BootstrapAdmin{
		Email:     m.Email,
		RoleCode:  m.RoleCode,
		Note:      m.Note,
		GrantedAt: m.GrantedAt,
	}
}
