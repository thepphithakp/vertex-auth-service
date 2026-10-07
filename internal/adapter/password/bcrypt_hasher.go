// Package password แปลงรหัสผ่านเป็น hash ด้วย bcrypt
//
// ไลบรารี bcrypt กับค่า cost ไม่รั่วออกจากแพ็กเกจนี้ — ชั้น application
// เห็นแค่ port.PasswordHasher
package password

import (
	"golang.org/x/crypto/bcrypt"

	"vertex-auth-service/internal/port"
)

// DefaultCost คือค่าเดิมที่ handleSignup ใช้ (bcrypt.GenerateFromPassword cost 10)
//
// ⚠️ ห้ามลดค่านี้ — hash ที่เก็บไว้แล้วยังเทียบได้เพราะ CompareHashAndPassword
//
//	อ่าน cost จากตัว hash เอง แต่บัญชีที่สมัครใหม่จะอ่อนลงทันที
const DefaultCost = 10

// BcryptHasher implements port.PasswordHasher
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher รับ cost เข้ามา ใส่ 0 เพื่อใช้ DefaultCost
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost == 0 {
		cost = DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Compare คืน nil เมื่อรหัสผ่านตรงกับ hash
//
// cost ที่ใช้เทียบมาจากตัว hash เอง ไม่ใช่ h.cost — hash ที่สร้างด้วย cost
// คนละค่าจึงยังเทียบผ่าน
func (h *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ยืนยันตอน compile ว่ายังตรงกับ port
var _ port.PasswordHasher = (*BcryptHasher)(nil)
