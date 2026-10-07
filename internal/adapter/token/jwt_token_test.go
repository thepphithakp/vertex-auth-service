package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
)

func privPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

// newEphemeralService สร้าง service ที่ถือคู่กุญแจใหม่เอี่ยม
//
// เทสต์ไม่ควรต้องมีคีย์จริงบนดิสก์ — สิ่งที่ต้องพิสูจน์คือ token ที่เซ็นแล้ว
// verify กลับได้ ไม่ใช่ว่าคีย์ใบไหนถูกใช้ (keys/private.pem ถูก revoke
// และลบออกจาก repo ไปแล้วเมื่อ 2026-08-22)
func newEphemeralService(t *testing.T) *JWTTokenService {
	t.Helper()
	key := genKey(t)
	svc, err := NewJWTTokenService(Config{
		PrivateKeyPEM: privPEM(t, key),
		PublicKeysPEM: pubPEM(t, key),
	})
	if err != nil {
		t.Fatalf("สร้าง token service ไม่สำเร็จ: %v", err)
	}
	return svc
}

// TestGenerateToken ยืนยันว่า claim ครบและ token เดิมยังอ่านได้
//
// เดิมอยู่ใน rbac_integration_test.go และต้องต่อฐานข้อมูลเพราะคีย์กับ
// ฟังก์ชันเซ็นอยู่ในตัวแปร global ของ package main — ตอนนี้ไม่พึ่ง DB แล้ว
// จึงรันใน go test ./... ได้โดยไม่ต้องมี tag integration
func TestGenerateToken(t *testing.T) {
	svc := newEphemeralService(t)

	u := domain.User{ID: uuid.New(), Email: "a@b.c", FullName: "ทดสอบ"}
	tokenStr, err := svc.Issue(u, []string{domain.RoleSuperAdmin, domain.RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := jwt.ParseRSAPublicKeyFromPEM(svc.PublicKeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return pub, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("token ที่เพิ่งออกต้อง verify ผ่าน: %v", err)
	}

	claims := tok.Claims.(jwt.MapClaims)
	for _, k := range []string{"sub", "email", "name", "roles", "iat", "jti", "exp"} {
		if _, ok := claims[k]; !ok {
			t.Errorf("token ขาด claim %q", k)
		}
	}
	if got := domain.RolesFromClaims(claims); len(got) != 2 {
		t.Fatalf("roles = %v", got)
	}

	// อายุ token ต้องเท่าเดิม เพื่อไม่ให้ผู้ใช้ถูกบังคับ login ใหม่
	exp := int64(claims["exp"].(float64))
	if d := time.Until(time.Unix(exp, 0)); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("อายุ token = %v ต้องประมาณ 72 ชั่วโมงเหมือนเดิม", d)
	}
}

// TestVerify_RoundTrip ยืนยันว่า token ที่ service ออกเอง ตรวจกลับด้วย
// service ใบเดียวกันได้ และได้ claims ที่ชั้น application ใช้ต่อได้
func TestVerify_RoundTrip(t *testing.T) {
	svc := newEphemeralService(t)

	u := domain.User{ID: uuid.New(), Email: "a@b.c", FullName: "ทดสอบ"}
	tokenStr, err := svc.Issue(u, []string{domain.RoleSuperAdmin, domain.RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := svc.Verify(tokenStr)
	if err != nil {
		t.Fatalf("token ที่เพิ่งออกต้องตรวจผ่าน: %v", err)
	}
	if claims.UserID != u.ID.String() {
		t.Errorf("UserID = %q ต้องการ %q", claims.UserID, u.ID.String())
	}
	if !domain.HasRole(claims.Roles, domain.RoleSuperAdmin) {
		t.Errorf("roles = %v ต้องมี SUPER_ADMIN", claims.Roles)
	}

	if _, err := svc.Verify("ไม่ใช่ token"); err == nil {
		t.Fatal("ค่าที่ไม่ใช่ token ต้องถูกปฏิเสธ")
	}
}
