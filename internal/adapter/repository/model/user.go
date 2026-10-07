// Package model รวม GORM model ที่แยกจาก domain entity
// domain ไม่มี tag ของ framework ใดๆ ส่วน model รู้เรื่องตารางและ column
package model

import (
	"time"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
)

type User struct {
	ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Email         string    `gorm:"uniqueIndex;not null"`
	PasswordHash  *string
	FullName      string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (User) TableName() string { return "users" }

func (m *User) ToDomain() domain.User {
	return domain.User{
		ID:            m.ID,
		Email:         m.Email,
		PasswordHash:  m.PasswordHash,
		FullName:      m.FullName,
		EmailVerified: m.EmailVerified,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

func UserFromDomain(u domain.User) User {
	return User{
		ID:            u.ID,
		Email:         u.Email,
		PasswordHash:  u.PasswordHash,
		FullName:      u.FullName,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// OAuthIdentity ผูกบัญชีกับ provider ภายนอก
//
// ⚠️ ชื่อตารางคือ "o_auth_identities" ไม่ใช่ "oauth_identities"
//
//	มาจากการแปลง OAuthIdentity เป็น snake_case ของ GORM ตอนที่ยังไม่มี
//	TableName() และตารางจริงบน production ใช้ชื่อนี้ — แก้แล้วทุก query พัง
type OAuthIdentity struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index"`
	Provider   string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_provider_provider_id"`
	ProviderID string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_provider_provider_id"`
	CreatedAt  time.Time
}

func (OAuthIdentity) TableName() string { return "o_auth_identities" }

func (m *OAuthIdentity) ToDomain() domain.OAuthIdentity {
	return domain.OAuthIdentity{
		ID:         m.ID,
		UserID:     m.UserID,
		Provider:   m.Provider,
		ProviderID: m.ProviderID,
		CreatedAt:  m.CreatedAt,
	}
}

func OAuthIdentityFromDomain(o domain.OAuthIdentity) OAuthIdentity {
	return OAuthIdentity{
		ID:         o.ID,
		UserID:     o.UserID,
		Provider:   o.Provider,
		ProviderID: o.ProviderID,
		CreatedAt:  o.CreatedAt,
	}
}
