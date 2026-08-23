//go:build integration

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ไม่ได้ตั้ง TEST_DATABASE_URL — ข้าม integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("ต่อฐานข้อมูลไม่ได้: %v", err)
	}
	dbConn = db
	return db
}

func createUser(t *testing.T, db *gorm.DB, email string, verified bool) User {
	t.Helper()
	u := User{ID: uuid.New(), Email: email, FullName: "ทดสอบ", EmailVerified: verified}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM user_roles WHERE user_id = ?`, u.ID)
		db.Exec(`DELETE FROM users WHERE id = ?`, u.ID)
	})
	return u
}

// TestSchemaReady ตรวจว่า Flyway migration รันครบ
func TestSchemaReady(t *testing.T) {
	db := setupTestDB(t)
	for _, tbl := range []string{"roles", "user_roles", "bootstrap_admins"} {
		if !db.Migrator().HasTable(tbl) {
			t.Errorf("ไม่พบตาราง %s", tbl)
		}
	}
	if !db.Migrator().HasColumn(&User{}, "email_verified") {
		t.Error("users ไม่มี column email_verified")
	}

	var n int64
	db.Model(&Role{}).Count(&n)
	if n < 3 {
		t.Errorf("role ในระบบ = %d ต้องการอย่างน้อย 3 (SUPER_ADMIN, PET_ADMIN, USER)", n)
	}
}

// TestBootstrapAdmin_RequiresVerifiedEmail คือ test ความปลอดภัยที่สำคัญที่สุดของเฟสนี้
//
// handleSignup สมัครด้วย password ได้โดยไม่ยืนยันอีเมล
// ถ้า grant โดยดูแค่สตริงอีเมล คนอื่นสมัครด้วยอีเมลที่อยู่ในรายการก่อนเจ้าตัว
// แล้วได้ SUPER_ADMIN ไปทันที
func TestBootstrapAdmin_RequiresVerifiedEmail(t *testing.T) {
	db := setupTestDB(t)

	email := "bootstrap-test-" + uuid.NewString()[:8] + "@example.com"
	if err := db.Exec(`INSERT INTO bootstrap_admins (email, role_code, note)
	                   VALUES (?, 'SUPER_ADMIN', 'test')`, email).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM bootstrap_admins WHERE email = ?`, email) })

	t.Run("อีเมลยังไม่ยืนยัน → ไม่ได้สิทธิ์", func(t *testing.T) {
		u := createUser(t, db, email, false)
		reconcileBootstrapAdmin(db, u)
		if hasRole(rolesForUser(db, u.ID), RoleSuperAdmin) {
			t.Fatal("🚨 บัญชีที่ยังไม่ยืนยันอีเมลได้ SUPER_ADMIN — ช่องโหว่ชิงบัญชี")
		}
	})

	t.Run("ยืนยันอีเมลแล้ว → ได้สิทธิ์", func(t *testing.T) {
		u := createUser(t, db, "verified-"+email, true)
		db.Exec(`UPDATE bootstrap_admins SET email = ? WHERE email = ?`, "verified-"+email, email)
		defer db.Exec(`UPDATE bootstrap_admins SET email = ? WHERE email = ?`, email, "verified-"+email)

		reconcileBootstrapAdmin(db, u)
		if !hasRole(rolesForUser(db, u.ID), RoleSuperAdmin) {
			t.Fatal("บัญชีที่ยืนยันอีเมลแล้วต้องได้ SUPER_ADMIN")
		}
	})

	t.Run("เรียกซ้ำต้องไม่พัง", func(t *testing.T) {
		u := createUser(t, db, "idem-"+email, true)
		db.Exec(`UPDATE bootstrap_admins SET email = ? WHERE email LIKE ?`, "idem-"+email, "%"+email)
		defer db.Exec(`UPDATE bootstrap_admins SET email = ? WHERE email = ?`, email, "idem-"+email)

		reconcileBootstrapAdmin(db, u)
		reconcileBootstrapAdmin(db, u)
		roles := rolesForUser(db, u.ID)
		count := 0
		for _, r := range roles {
			if r == RoleSuperAdmin {
				count++
			}
		}
		if count > 1 {
			t.Fatalf("role ซ้ำ %d ครั้ง", count)
		}
	})
}

func TestRolesForUser_DefaultsToUser(t *testing.T) {
	db := setupTestDB(t)
	u := createUser(t, db, "norole-"+uuid.NewString()[:8]+"@example.com", false)

	roles := rolesForUser(db, u.ID)
	if len(roles) != 1 || roles[0] != RoleUser {
		t.Fatalf("roles = %v ต้องการ [USER]", roles)
	}

	ensureDefaultRole(db, u.ID)
	if roles := rolesForUser(db, u.ID); len(roles) != 1 || roles[0] != RoleUser {
		t.Fatalf("roles = %v", roles)
	}
}

// TestGenerateToken ยืนยันว่า claim ครบและ token เดิมยังอ่านได้
func TestGenerateToken(t *testing.T) {
	setupTestDB(t)
	useEphemeralKeys(t)
	initRSAKeys()

	u := User{ID: uuid.New(), Email: "a@b.c", FullName: "ทดสอบ"}
	tokenStr, err := generateToken(u, []string{RoleSuperAdmin, RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
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
	if got := rolesFromClaims(claims); len(got) != 2 {
		t.Fatalf("roles = %v", got)
	}

	// อายุ token ต้องเท่าเดิม เพื่อไม่ให้ผู้ใช้ถูกบังคับ login ใหม่
	exp := int64(claims["exp"].(float64))
	if d := time.Until(time.Unix(exp, 0)); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("อายุ token = %v ต้องประมาณ 72 ชั่วโมงเหมือนเดิม", d)
	}
}

func TestCountSuperAdmins(t *testing.T) {
	db := setupTestDB(t)
	before, err := countSuperAdmins(db)
	if err != nil {
		t.Fatal(err)
	}

	u := createUser(t, db, "sa-"+uuid.NewString()[:8]+"@example.com", true)
	db.Exec(`INSERT INTO user_roles (user_id, role_code) VALUES (?, 'SUPER_ADMIN')`, u.ID)

	after, _ := countSuperAdmins(db)
	if after != before+1 {
		t.Fatalf("นับได้ %d ต้องการ %d", after, before+1)
	}
}

// useEphemeralKeys สร้างคู่กุญแจใหม่ให้เทสต์ใช้ แล้วคืนค่าเดิมเมื่อเทสต์จบ
//
// เดิมเทสต์เรียก initRSAKeys() ตรงๆ ซึ่ง fallback ไปอ่าน keys/private.pem
// พอคีย์ใบนั้นถูก revoke และลบออกจาก repo (2026-08-22) initRSAKeys จึง
// log.Fatal ทำให้ทั้ง package ล้มทั้งที่เทสต์ตัวอื่นผ่านหมด
//
// เทสต์ไม่ควรต้องมีคีย์จริงบนดิสก์อยู่แล้ว — สิ่งที่ต้องพิสูจน์คือ
// token ที่เซ็นแล้ว verify กลับได้ ไม่ใช่ว่าคีย์ใบไหนถูกใช้
func useEphemeralKeys(t *testing.T) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("สร้างคีย์ไม่สำเร็จ: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("แปลง public key ไม่สำเร็จ: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	oldPriv, oldPubs, oldPub := jwtPrivateKeyPEM, jwtPublicKeysPEM, jwtPublicKeyPEM
	t.Cleanup(func() {
		jwtPrivateKeyPEM, jwtPublicKeysPEM, jwtPublicKeyPEM = oldPriv, oldPubs, oldPub
	})

	jwtPrivateKeyPEM = string(privPEM)
	jwtPublicKeysPEM = string(pubPEM)
	jwtPublicKeyPEM = ""
}
