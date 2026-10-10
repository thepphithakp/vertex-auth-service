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
// 🔴 ไม่มี json tag แล้ว — เดิมมีเพราะ handler เคยเสียบ struct นี้ลง
// response ตรงๆ (/signup, /login, /google) ย้าย wire format ไปอยู่
// adapter/handler.userResponse แทน (ตามแบบ pet-service/chat-service)
// domain ไม่ควรรู้จัก JSON เลย
type User struct {
	ID    uuid.UUID
	Email string

	// PasswordHash เป็น pointer เพื่อแยก "สมัครด้วยรหัสผ่าน" (มีค่า)
	// ออกจาก "สมัครผ่าน provider ภายนอกเท่านั้น" (nil)
	PasswordHash *string

	FullName string

	// EmailVerified จำเป็นต่อความปลอดภัยของ bootstrap admin
	// signup ด้วย password ตั้งเป็น false เสมอ — login ผ่าน Google ถึงจะเป็น true
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// OAuthIdentity ผูกบัญชีกับ provider ภายนอกหนึ่งราย — ไม่มีใครส่งค่านี้
// กลับไปให้ client เลย จึงไม่มี json tag เหมือนกัน
type OAuthIdentity struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Provider   string // e.g., "apple", "google", "facebook"
	ProviderID string // The sub from the provider
	CreatedAt  time.Time
}

// ProviderGoogle คือค่าที่เก็บในคอลัมน์ provider สำหรับ Google
const ProviderGoogle = "google"
