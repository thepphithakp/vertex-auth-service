//go:build integration

package bootstrap

import (
	"testing"

	"vertex-auth-service/internal/adapter/handler"
	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/domain"
)

// TestSchemaReady ตรวจว่า Flyway migration รันครบ
func TestSchemaReady(t *testing.T) {
	db := openTestDB(t)
	for _, tbl := range []string{"roles", "user_roles", "bootstrap_admins"} {
		if !db.Migrator().HasTable(tbl) {
			t.Errorf("ไม่พบตาราง %s", tbl)
		}
	}
	if !db.Migrator().HasColumn(&model.User{}, "email_verified") {
		t.Error("users ไม่มี column email_verified")
	}

	var n int64
	db.Model(&model.Role{}).Count(&n)
	if n < 3 {
		t.Errorf("role ในระบบ = %d ต้องการอย่างน้อย 3 (SUPER_ADMIN, PET_ADMIN, USER)", n)
	}
}

// addBootstrapAdmin ใส่อีเมลลงรายการ bootstrap_admins แล้วลบออกเมื่อเทสต์จบ
func addBootstrapAdmin(t *testing.T, env *testEnv, email string) {
	t.Helper()
	if err := env.db.Exec(`INSERT INTO bootstrap_admins (email, role_code, note)
	                       VALUES (?, 'SUPER_ADMIN', 'test')`, email).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.db.Exec(`DELETE FROM bootstrap_admins WHERE email = ?`, email) })
}

// TestBootstrapAdmin_RequiresVerifiedEmail คือ test ความปลอดภัยที่สำคัญที่สุดของเฟสนี้
//
// Signup สมัครด้วย password ได้โดยไม่ยืนยันอีเมล
// ถ้า grant โดยดูแค่สตริงอีเมล คนอื่นสมัครด้วยอีเมลที่อยู่ในรายการก่อนเจ้าตัว
// แล้วได้ SUPER_ADMIN ไปทันที
//
// 🔧 เปลี่ยนจากฉบับก่อน refactor เฉพาะวิธีกระตุ้นโค้ด: เดิมเรียก
//
//	reconcileBootstrapAdmin(db, u) ตรงๆ ได้เพราะอยู่ใน package main เดียวกัน
//	ตอนนี้ขั้นตอนนั้นเป็น method ที่ไม่ export ของ AuthService (ทำงานเป็น
//	ผลข้างเคียงของการออก token) เทสต์จึงยิง POST /login ผ่าน app จริงแทน
//	เส้นทางโค้ดที่ถูกทดสอบและทุกข้อที่ยืนยันยังเหมือนเดิม
func TestBootstrapAdmin_RequiresVerifiedEmail(t *testing.T) {
	env := testApp(t)

	const password = "bootstrap-pw"
	hash, err := bcryptHashForTest(password)
	if err != nil {
		t.Fatal(err)
	}

	login := func(t *testing.T, email string) {
		t.Helper()
		resp, body := doJSON(t, env.app, "POST", "/api/v1/auth/login",
			handler.LoginRequest{Email: email, Password: password}, "")
		if resp.StatusCode != 200 {
			t.Fatalf("login status = %d body=%v", resp.StatusCode, body)
		}
	}

	t.Run("อีเมลยังไม่ยืนยัน → ไม่ได้สิทธิ์", func(t *testing.T) {
		email := newTestEmail("bootstrap-unverified")
		addBootstrapAdmin(t, env, email)
		u := createUserWithPassword(t, env.db, email, hash, false)

		login(t, email)

		if domain.HasRole(env.rolesForUser(u.ID), domain.RoleSuperAdmin) {
			t.Fatal("🚨 บัญชีที่ยังไม่ยืนยันอีเมลได้ SUPER_ADMIN — ช่องโหว่ชิงบัญชี")
		}
	})

	t.Run("ยืนยันอีเมลแล้ว → ได้สิทธิ์", func(t *testing.T) {
		email := newTestEmail("bootstrap-verified")
		addBootstrapAdmin(t, env, email)
		u := createUserWithPassword(t, env.db, email, hash, true)

		login(t, email)

		if !domain.HasRole(env.rolesForUser(u.ID), domain.RoleSuperAdmin) {
			t.Fatal("บัญชีที่ยืนยันอีเมลแล้วต้องได้ SUPER_ADMIN")
		}
	})

	t.Run("เรียกซ้ำต้องไม่พัง", func(t *testing.T) {
		email := newTestEmail("bootstrap-idem")
		addBootstrapAdmin(t, env, email)
		u := createUserWithPassword(t, env.db, email, hash, true)

		login(t, email)
		login(t, email)

		roles := env.rolesForUser(u.ID)
		count := 0
		for _, r := range roles {
			if r == domain.RoleSuperAdmin {
				count++
			}
		}
		if count > 1 {
			t.Fatalf("role ซ้ำ %d ครั้ง", count)
		}
	})
}
