package port

// PasswordHasher แปลงรหัสผ่านเป็น hash และเทียบกลับ
//
// ซ่อนทั้งอัลกอริทึมและ cost ไว้ที่ adapter — ชั้น application ไม่ต้องรู้ว่า
// เป็น bcrypt
type PasswordHasher interface {
	Hash(password string) (string, error)

	// Compare คืน nil เมื่อรหัสผ่านตรงกับ hash
	Compare(hash, password string) error
}
