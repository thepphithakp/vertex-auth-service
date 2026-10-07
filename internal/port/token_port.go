package port

import (
	"vertex-auth-service/internal/domain"
)

// Claims คือสิ่งที่ชั้น application ต้องรู้จาก token หนึ่งใบ
//
// จงใจไม่ใช้ jwt.MapClaims เพื่อให้ไลบรารี JWT ไม่รั่วออกจาก adapter
type Claims struct {
	// UserID เป็นสตริง ไม่ใช่ uuid.UUID
	//
	// เก็บค่าดิบจาก claim "sub" ไว้แบบเดิม เพราะโค้ดเดิมเอาค่านี้ใส่
	// c.Locals("userId") เป็นสตริง แล้วค่อย parse ตอนใช้ — จุดที่ parse ล้ม
	// จึงตอบสถานะต่างกันกับจุดที่ตรวจ token
	UserID string
	Roles  []string
}

// TokenService ออกและตรวจ access token
type TokenService interface {
	// Issue เซ็น access token ให้ผู้ใช้พร้อม role ที่ให้มา
	Issue(user domain.User, roles []string) (string, error)

	// Verify ตรวจลายเซ็นและอายุ แล้วคืน claims ที่ใช้ได้
	//
	// คืน domain.ErrTokenInvalid / ErrTokenClaims / ErrTokenSubject
	// ตามชนิดของปัญหา เพราะข้อความที่ตอบผู้เรียกต่างกัน
	Verify(tokenString string) (Claims, error)
}

// KeyInfo สรุปสถานะคีย์ของ pod นี้ ใช้ตรวจตอน rotate ว่าแต่ละ pod เซ็นด้วยใบไหน
type KeyInfo struct {
	SigningKeyID   string
	AcceptedKeyIDs []string
	TokenTTL       string
}

// KeyInspector เปิดเผยข้อมูลคีย์แบบอ่านอย่างเดียว
//
// แยกจาก TokenService เพราะเป็นเรื่องของการดูแลระบบ (endpoint /public-key
// กับ /key-info) ไม่ใช่การออกหรือตรวจ token
type KeyInspector interface {
	// PublicKeyPEM คืน PEM ดิบของ public key ทุกใบที่ยอมรับ ต่อกันเป็นก้อนเดียว
	//
	// service ปลายทางเอาไปใส่ JWT_PUBLIC_KEYS ได้ตรงๆ
	PublicKeyPEM() []byte

	KeyInfo() KeyInfo
}
