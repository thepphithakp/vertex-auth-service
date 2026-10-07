// Package domain รวม entity และกฎที่ไม่ขึ้นกับ framework ใดๆ
//
// ไม่มี tag ของ GORM ที่นี่ — ชั้น adapter มี row struct ของตัวเองที่รู้เรื่อง
// ตารางและ column (ดู internal/adapter/repository/model)
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User คือบัญชีผู้ใช้หนึ่งคน
//
// json tag ยังอยู่เพราะ handler คืน struct นี้ลง response ตรงๆ
// (รูปร่าง response ของ /signup, /login, /google เป็นสัญญากับ client อยู่แล้ว)
type User struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`

	// PasswordHash เป็น pointer เพื่อแยก "สมัครด้วยรหัสผ่าน" (มีค่า)
	// ออกจาก "สมัครผ่าน provider ภายนอกเท่านั้น" (nil)
	PasswordHash *string `json:"-"`

	FullName string `json:"fullName"`

	// EmailVerified จำเป็นต่อความปลอดภัยของ bootstrap admin
	// signup ด้วย password ตั้งเป็น false เสมอ — login ผ่าน Google ถึงจะเป็น true
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// OAuthIdentity ผูกบัญชีกับ provider ภายนอกหนึ่งราย
type OAuthIdentity struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"userId"`
	Provider   string    `json:"provider"`   // e.g., "apple", "google", "facebook"
	ProviderID string    `json:"providerId"` // The sub from the provider
	CreatedAt  time.Time `json:"createdAt"`
}

// ProviderGoogle คือค่าที่เก็บในคอลัมน์ provider สำหรับ Google
const ProviderGoogle = "google"
