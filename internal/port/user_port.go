// Package port ประกาศสัญญาระหว่างชั้น application กับโลกภายนอก
//
// ชั้น application พึ่งพาแต่ interface ในแพ็กเกจนี้ ไม่รู้จัก GORM, JWT,
// Fiber หรือ SDK ของ Google เลย
package port

import (
	"context"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
)

// UserRepository เก็บและอ่านบัญชีผู้ใช้
type UserRepository interface {
	// Create สร้างบัญชีใหม่ แล้วเขียน CreatedAt/UpdatedAt กลับเข้า user
	//
	// ⚠️ คืน error ดิบ ไม่แปลงเป็น "อีเมลซ้ำ" ให้ — เพราะสถานะที่ตอบผู้เรียก
	//    ขึ้นกับว่าใครเรียก: /signup ตอบ 409 ส่วน /google ตอบ 500
	//    กับ error ตัวเดียวกัน (พฤติกรรมเดิม) การตัดสินจึงอยู่ที่ชั้น application
	Create(ctx context.Context, user *domain.User) error

	// FindByEmail หาบัญชีจากอีเมล คืน domain.ErrUserNotFound เมื่อไม่พบ
	FindByEmail(ctx context.Context, email string) (domain.User, error)

	// FindByID หาบัญชีจาก id คืน domain.ErrUserNotFound เมื่อไม่พบ
	FindByID(ctx context.Context, id uuid.UUID) (domain.User, error)

	// Save เขียนทับทุกคอลัมน์ของบัญชีที่มีอยู่แล้ว
	//
	// เป็น UPDATE ทั้งแถวแบบเดียวกับ gorm.Save ของโค้ดเดิม
	// ไม่ใช่การแก้เฉพาะคอลัมน์ที่เปลี่ยน
	Save(ctx context.Context, user *domain.User) error

	// MarkEmailVerified ตั้ง email_verified = true ให้บัญชีหนึ่ง
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error

	// FindAll คืนบัญชีทั้งหมด ใช้กับ GET /users
	FindAll(ctx context.Context) ([]domain.User, error)

	// List คืนบัญชีเรียงตามวันที่สร้างล่าสุด กรองด้วย search ได้
	//
	// search ว่าง = ไม่กรอง — limit บังคับเสมอ
	List(ctx context.Context, search string, limit int) ([]domain.User, error)
}
