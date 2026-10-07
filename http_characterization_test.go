//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ไฟล์นี้คือ pin ของ Refactoring playbook — จับพฤติกรรม HTTP ปัจจุบันไว้
// ก่อนย้ายโครงสร้างไป hexagonal ไม่ใช่เทสต์ฟีเจอร์ใหม่ ย้ายเสร็จแล้วต้องรัน
// ไฟล์นี้ผ่านเหมือนเดิมทุกเคส (ปรับได้แค่วิธีสร้าง app สำหรับเทสต์)
//
// จุดที่ไม่เคยมีเทสต์คุ้มมาก่อนเลยและเสี่ยงที่สุดถ้า refactor พลาด:
// self-lockout กับ last-SUPER_ADMIN protection ใน handleAdminUpdateRoles

func testApp(t *testing.T) *fiber.App {
	t.Helper()
	setupTestDB(t)
	useEphemeralKeys(t)
	initRSAKeys()
	return buildApp()
}

func doJSON(t *testing.T, app *fiber.App, method, path string, body any, token string) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed) // ไม่ใช่ JSON ทุก response (public-key เป็น text ดิบ) — เทสต์นั้นไม่เรียก helper นี้
	return resp, parsed
}

func newTestEmail(prefix string) string {
	return prefix + "-" + uuid.NewString()[:8] + "@example.com"
}

// --- Signup ---------------------------------------------------------------

func TestHTTP_Signup_HappyPath(t *testing.T) {
	app := testApp(t)
	email := newTestEmail("signup")

	resp, body := doJSON(t, app, "POST", "/api/v1/auth/signup", SignupRequest{
		Email: email, Password: "s3cret-pass", FullName: "ทดสอบ สมัคร",
	}, "")
	t.Cleanup(func() { dbConn.Exec(`DELETE FROM users WHERE email = ?`, email) })

	if resp.StatusCode != 201 {
		t.Fatalf("status = %d ต้องการ 201, body=%v", resp.StatusCode, body)
	}
	if tok, _ := body["token"].(string); tok == "" {
		t.Error("ต้องมี token")
	}
	user, _ := body["user"].(map[string]any)
	if user["email"] != email {
		t.Errorf("user.email = %v ต้องการ %s", user["email"], email)
	}
	if user["emailVerified"] != false {
		t.Error("สมัครด้วย password ต้อง emailVerified = false เสมอ")
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 1 || roles[0] != "USER" {
		t.Errorf("roles = %v ต้องการ [USER]", roles)
	}
}

func TestHTTP_Signup_DuplicateEmail(t *testing.T) {
	app := testApp(t)
	email := newTestEmail("dup")
	createUser(t, dbConn, email, false)

	resp, _ := doJSON(t, app, "POST", "/api/v1/auth/signup", SignupRequest{
		Email: email, Password: "whatever1", FullName: "x",
	}, "")
	if resp.StatusCode != 409 {
		t.Fatalf("status = %d ต้องการ 409 (อีเมลซ้ำ)", resp.StatusCode)
	}
}

func TestHTTP_Signup_MissingFields(t *testing.T) {
	app := testApp(t)
	resp, _ := doJSON(t, app, "POST", "/api/v1/auth/signup", SignupRequest{Email: "", Password: ""}, "")
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400", resp.StatusCode)
	}
}

// --- Login ------------------------------------------------------------------

func TestHTTP_Login_HappyPath(t *testing.T) {
	app := testApp(t)
	email := newTestEmail("login")
	hash, _ := bcryptHashForTest("correct-pw")
	u := User{ID: uuid.New(), Email: email, PasswordHash: &hash, FullName: "ล็อกอิน"}
	if err := dbConn.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbConn.Exec(`DELETE FROM users WHERE id = ?`, u.ID) })

	resp, body := doJSON(t, app, "POST", "/api/v1/auth/login", LoginRequest{Email: email, Password: "correct-pw"}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200, body=%v", resp.StatusCode, body)
	}
	if tok, _ := body["token"].(string); tok == "" {
		t.Error("ต้องมี token")
	}
}

func TestHTTP_Login_WrongPassword(t *testing.T) {
	app := testApp(t)
	email := newTestEmail("wrongpw")
	hash, _ := bcryptHashForTest("correct-pw")
	u := User{ID: uuid.New(), Email: email, PasswordHash: &hash, FullName: "x"}
	dbConn.Create(&u)
	t.Cleanup(func() { dbConn.Exec(`DELETE FROM users WHERE id = ?`, u.ID) })

	resp, _ := doJSON(t, app, "POST", "/api/v1/auth/login", LoginRequest{Email: email, Password: "wrong"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

func TestHTTP_Login_NonexistentEmail(t *testing.T) {
	app := testApp(t)
	resp, _ := doJSON(t, app, "POST", "/api/v1/auth/login", LoginRequest{Email: newTestEmail("ghost"), Password: "x"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

// --- Me / lookup / keys ------------------------------------------------------

func TestHTTP_Me_ValidToken(t *testing.T) {
	app := testApp(t)
	u := createUser(t, dbConn, newTestEmail("me"), false)
	tok, _, err := issueToken(u)
	if err != nil {
		t.Fatal(err)
	}

	resp, body := doJSON(t, app, "GET", "/api/v1/auth/me", nil, tok)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200, body=%v", resp.StatusCode, body)
	}
	if body["email"] != u.Email {
		t.Errorf("email = %v ต้องการ %s", body["email"], u.Email)
	}
}

func TestHTTP_Me_NoToken(t *testing.T) {
	app := testApp(t)
	resp, _ := doJSON(t, app, "GET", "/api/v1/auth/me", nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

func TestHTTP_PublicKey_ReturnsPEM(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest("GET", "/api/v1/auth/public-key", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !bytes.Contains(raw, []byte("PUBLIC KEY")) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestHTTP_KeyInfo(t *testing.T) {
	app := testApp(t)
	resp, body := doJSON(t, app, "GET", "/api/v1/auth/key-info", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body["signingKeyId"] == "" || body["signingKeyId"] == nil {
		t.Error("ต้องมี signingKeyId")
	}
}

func TestHTTP_Health(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest("GET", "/health", nil)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// --- Admin: การเข้าถึง --------------------------------------------------------

func TestHTTP_Admin_RejectsNonSuperAdmin(t *testing.T) {
	app := testApp(t)
	u := createUser(t, dbConn, newTestEmail("plain"), false)
	ensureDefaultRole(dbConn, u.ID)
	tok, _, _ := issueToken(u)

	resp, _ := doJSON(t, app, "GET", "/api/v1/auth/admin/users", nil, tok)
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d ต้องการ 403 (ไม่ใช่ SUPER_ADMIN)", resp.StatusCode)
	}
}

func mustSuperAdmin(t *testing.T, email string) (User, string) {
	t.Helper()
	u := createUser(t, dbConn, email, true)
	if err := dbConn.Exec(`INSERT INTO user_roles (user_id, role_code) VALUES (?, 'SUPER_ADMIN')`, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	tok, _, err := issueToken(u)
	if err != nil {
		t.Fatal(err)
	}
	return u, tok
}

func TestHTTP_Admin_ListUsersAndRoles(t *testing.T) {
	app := testApp(t)
	_, tok := mustSuperAdmin(t, newTestEmail("admin-list"))

	resp, _ := doJSON(t, app, "GET", "/api/v1/auth/admin/users", nil, tok)
	if resp.StatusCode != 200 {
		t.Fatalf("list users status = %d", resp.StatusCode)
	}

	req := httptest.NewRequest("GET", "/api/v1/auth/admin/roles", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp2, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("list roles status = %d", resp2.StatusCode)
	}
}

func TestHTTP_Admin_UpdateRoles_HappyPath(t *testing.T) {
	app := testApp(t)
	_, actorTok := mustSuperAdmin(t, newTestEmail("actor"))
	target := createUser(t, dbConn, newTestEmail("target"), false)
	ensureDefaultRole(dbConn, target.ID)

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, body := doJSON(t, app, "PUT", path, updateRolesRequest{Roles: []string{"PET_ADMIN"}}, actorTok)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%v", resp.StatusCode, body)
	}
	roles, _ := body["roles"].([]any)
	found := map[string]bool{}
	for _, r := range roles {
		found[r.(string)] = true
	}
	if !found["PET_ADMIN"] || !found["USER"] {
		t.Fatalf("roles = %v ต้องมีทั้ง PET_ADMIN และ USER (บังคับพื้นฐานเสมอ)", roles)
	}
}

func TestHTTP_Admin_UpdateRoles_UnknownRole(t *testing.T) {
	app := testApp(t)
	_, actorTok := mustSuperAdmin(t, newTestEmail("actor2"))
	target := createUser(t, dbConn, newTestEmail("target2"), false)

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, _ := doJSON(t, app, "PUT", path, updateRolesRequest{Roles: []string{"NOT_A_REAL_ROLE"}}, actorTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (role ไม่มีอยู่จริง)", resp.StatusCode)
	}
}

// TestHTTP_Admin_CannotRemoveOwnSuperAdmin คือเคสที่สำคัญที่สุดเคสหนึ่งของทั้งไฟล์
// ไม่เคยมีเทสต์คุ้มมาก่อนเลย — ถ้า refactor พลาดจุดนี้ SUPER_ADMIN ถอดสิทธิ์
// ตัวเองได้โดยไม่ตั้งใจ แล้วอาจไม่เหลือใครแก้กลับได้เลย
func TestHTTP_Admin_CannotRemoveOwnSuperAdmin(t *testing.T) {
	app := testApp(t)
	self, selfTok := mustSuperAdmin(t, newTestEmail("self-lockout"))

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", self.ID)
	resp, _ := doJSON(t, app, "PUT", path, updateRolesRequest{Roles: []string{"USER"}}, selfTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (ถอด SUPER_ADMIN ของตัวเองไม่ได้)", resp.StatusCode)
	}

	roles := rolesForUser(dbConn, self.ID)
	if !hasRole(roles, RoleSuperAdmin) {
		t.Fatal("🚨 SUPER_ADMIN หลุดจาก role ของตัวเองทั้งที่ควรถูกบล็อก")
	}
}

// TestHTTP_Admin_CannotRemoveLastSuperAdmin อีกเคสที่ไม่เคยมีเทสต์คุ้ม คนละ
// เคสกับ self-lockout: actor ที่ "ไม่ใช่" target เป็นคนพยายามถอด SUPER_ADMIN
// ของคนสุดท้ายที่เหลือในระบบ
//
// การตั้งฉากนี้ยากกว่าที่คิด: ต้อง requireRole(SUPER_ADMIN) ผ่านก่อนถึงจะเรียก
// endpoint นี้ได้เลย ถ้า SUPER_ADMIN ในระบบ (ตาม user_roles) เหลือแค่คนเดียว
// คนที่เรียกได้ก็มีแต่คนๆ นั้น ทำให้ actor กับ target จะเป็นคนเดียวกันเสมอ
// (กลายเป็น self-lockout ไปโดยปริยาย ไม่ใช่เคสที่ต้องการ)
//
// ทางเดียวที่ actor ≠ target เกิดขึ้นได้จริงคือผ่านทางผ่านสำรองใน requireRole
// (isBootstrapAdminFromToken) — บัญชีที่อยู่ใน bootstrap_admins และยืนยันอีเมล
// แล้วผ่าน middleware ได้โดยไม่ต้องมี role SUPER_ADMIN ใน user_roles เลย
// สถานการณ์นี้ไม่ได้แต่งขึ้นลอยๆ แต่เป็นทางที่ระบบออกแบบไว้จริงสำหรับช่วง
// เปลี่ยนผ่าน (ดูคอมเมนต์ requireRole ใน admin.go)
func TestHTTP_Admin_CannotRemoveLastSuperAdmin(t *testing.T) {
	app := testApp(t)

	// target คือ SUPER_ADMIN ตัวจริงหนึ่งเดียวที่มีอยู่ในเทสต์นี้ (DB ทดสอบ
	// แยกจาก production จึงเริ่มจากศูนย์ ไม่มี SUPER_ADMIN เดิมมาปน)
	target, _ := mustSuperAdmin(t, newTestEmail("last-admin-target"))

	// actor ไม่มี role SUPER_ADMIN เลย แต่ยืนยันอีเมลแล้วและอยู่ใน
	// bootstrap_admins จึงผ่าน requireRole ได้ทางสำรอง
	actorEmail := newTestEmail("bootstrap-actor")
	actor := createUser(t, dbConn, actorEmail, true)
	if err := dbConn.Exec(`INSERT INTO bootstrap_admins (email, role_code, note) VALUES (?, 'SUPER_ADMIN', 'test')`,
		actorEmail).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbConn.Exec(`DELETE FROM bootstrap_admins WHERE email = ?`, actorEmail) })
	ensureDefaultRole(dbConn, actor.ID) // ให้มี role USER เฉยๆ ไม่มี SUPER_ADMIN

	// ⚠️ ห้ามใช้ issueToken(actor) ตรงนี้ — issueToken เรียก
	// reconcileBootstrapAdmin เป็นผลข้างเคียงเสมอ ซึ่งจะ grant SUPER_ADMIN
	// ให้ actor จริงใน user_roles ทันที (เพราะ email_verified=true และอยู่ใน
	// bootstrap_admins) ทำให้ระบบมี SUPER_ADMIN ตัวจริง 2 คนแทนที่จะเป็น 1
	// แล้วเทสต์นี้จะไม่ได้ทดสอบ "ทางผ่านสำรอง" เลย (เจอมาแล้วจากการรันจริง
	// รอบแรก — ไม่ใช่บั๊กของระบบ แต่เป็นจุดบกพร่องของการตั้งฉากเทสต์)
	//
	// ใช้ generateToken ตรงๆ แทน มอบแค่ role USER ให้ตรงกับโทเคนเก่าที่ออก
	// ก่อนมี reconcile logic จริงๆ (ซึ่งเป็นสถานการณ์ที่ทางผ่านสำรองนี้
	// ถูกออกแบบมาให้รองรับ)
	actorTok, err := generateToken(actor, []string{RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, _ := doJSON(t, app, "PUT", path, updateRolesRequest{Roles: []string{"USER"}}, actorTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (จะเหลือ SUPER_ADMIN ศูนย์คนในระบบ)", resp.StatusCode)
	}

	if !hasRole(rolesForUser(dbConn, target.ID), RoleSuperAdmin) {
		t.Fatal("🚨 SUPER_ADMIN คนสุดท้ายถูกถอดสิทธิ์ทั้งที่ควรถูกบล็อก")
	}
}

// bcryptHashForTest ใช้ cost ต่ำกว่า production (10) เพื่อให้เทสต์เร็วขึ้น
// ไม่กระทบพฤติกรรมที่ทดสอบเพราะ handleLogin เทียบด้วย bcrypt.CompareHashAndPassword
// ซึ่งอ่าน cost จากตัว hash เองอยู่แล้ว ไม่ต้องรู้ล่วงหน้า
func bcryptHashForTest(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 4)
	return string(hash), err
}
