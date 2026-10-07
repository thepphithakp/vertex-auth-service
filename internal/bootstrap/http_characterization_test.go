//go:build integration

package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/handler"
	"vertex-auth-service/internal/adapter/repository"
	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/adapter/token"
	"vertex-auth-service/internal/config"
	"vertex-auth-service/internal/domain"
)

// ไฟล์นี้คือ pin ของ Refactoring playbook — จับพฤติกรรม HTTP ปัจจุบันไว้
// ก่อนย้ายโครงสร้างไป hexagonal ไม่ใช่เทสต์ฟีเจอร์ใหม่ ย้ายเสร็จแล้วต้องรัน
// ไฟล์นี้ผ่านเหมือนเดิมทุกเคส (ปรับได้แค่วิธีสร้าง app สำหรับเทสต์)
//
// จุดที่ไม่เคยมีเทสต์คุ้มมาก่อนเลยและเสี่ยงที่สุดถ้า refactor พลาด:
// self-lockout กับ last-SUPER_ADMIN protection ใน AdminService.UpdateRoles
//
// สิ่งที่เปลี่ยนจากฉบับก่อน refactor: เดิมไฟล์นี้อยู่ใน package main แล้ว
// เรียกฟังก์ชันกับตัวแปร global ตรงๆ (buildApp, issueToken, dbConn, ...)
// ตอนนี้ประกอบ app ผ่าน NewApp แล้วถือ dependency ไว้ใน testEnv
// ชื่อเทสต์และสิ่งที่ยืนยันทุกข้อยังเหมือนเดิม

// testEnv รวมของที่เทสต์ต้องใช้ร่วมกัน แทนตัวแปร global ของ package main เดิม
type testEnv struct {
	app    *fiber.App
	db     *gorm.DB
	roles  *repository.GORMRoleRepository
	tokens *token.JWTTokenService
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ไม่ได้ตั้ง TEST_DATABASE_URL — ข้าม integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("ต่อฐานข้อมูลไม่ได้: %v", err)
	}
	return db
}

// ephemeralJWTConfig สร้างคู่กุญแจใหม่ให้เทสต์ใช้
//
// เดิมเทสต์เรียก initRSAKeys() ตรงๆ ซึ่ง fallback ไปอ่าน keys/private.pem
// พอคีย์ใบนั้นถูก revoke และลบออกจาก repo (2026-08-22) initRSAKeys จึง
// log.Fatal ทำให้ทั้ง package ล้มทั้งที่เทสต์ตัวอื่นผ่านหมด
//
// เทสต์ไม่ควรต้องมีคีย์จริงบนดิสก์อยู่แล้ว — สิ่งที่ต้องพิสูจน์คือ
// token ที่เซ็นแล้ว verify กลับได้ ไม่ใช่ว่าคีย์ใบไหนถูกใช้
//
// ต่างจาก useEphemeralKeys เดิมที่สลับค่าตัวแปร global แล้วคืนค่าตอนเทสต์จบ:
// ตอนนี้คืนค่า config ออกมาตรงๆ ไม่มี global ให้ต้องกู้คืน
func ephemeralJWTConfig(t *testing.T) config.JWTConfig {
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

	return config.JWTConfig{
		PrivateKeyPEM: string(privPEM),
		PublicKeysPEM: string(pubPEM),
	}
}

// testApp ประกอบ app จริงผ่าน NewApp — เส้นทางเดียวกับที่ cmd/server ใช้
func testApp(t *testing.T) *testEnv {
	t.Helper()

	db := openTestDB(t)
	cfg := config.Config{Port: config.DefaultPort, JWT: ephemeralJWTConfig(t)}

	app, err := NewApp(db, cfg)
	if err != nil {
		t.Fatalf("ประกอบ app ไม่สำเร็จ: %v", err)
	}

	// token service อีกใบที่ถือคีย์ชุดเดียวกับที่ NewApp ใช้ — ใช้ออก token
	// ให้เทสต์ ซึ่ง app ตรวจผ่านเพราะคีย์มาจาก cfg ก้อนเดียวกัน
	tokens, err := token.NewJWTTokenService(token.Config{
		PrivateKeyPEM: cfg.JWT.PrivateKeyPEM,
		PublicKeysPEM: cfg.JWT.PublicKeysPEM,
	})
	if err != nil {
		t.Fatalf("สร้าง token service ไม่สำเร็จ: %v", err)
	}

	return &testEnv{
		app:    app,
		db:     db,
		roles:  repository.NewGORMRoleRepository(db),
		tokens: tokens,
	}
}

// issueToken ออก token ให้ผู้ใช้พร้อม role ที่มีอยู่ในฐานข้อมูลตอนนี้
//
// ⚠️ ไม่เรียก reconcileBootstrapAdmin เหมือน AuthService.issueToken ตัวจริง
//
//	โดยตั้งใจ — ไม่มีเทสต์ไหนพึ่งผลข้างเคียงนั้น และ
//	TestHTTP_Admin_CannotRemoveLastSuperAdmin พึ่งการ "ไม่เกิด" ของมัน
//	(ดูคอมเมนต์ในเทสต์นั้น)
func (e *testEnv) issueToken(t *testing.T, user domain.User) (string, []string) {
	t.Helper()
	roles := e.roles.RolesForUser(context.Background(), user.ID)
	tok, err := e.tokens.Issue(user, roles)
	if err != nil {
		t.Fatal(err)
	}
	return tok, roles
}

func (e *testEnv) rolesForUser(userID uuid.UUID) []string {
	return e.roles.RolesForUser(context.Background(), userID)
}

func (e *testEnv) ensureDefaultRole(userID uuid.UUID) {
	e.roles.EnsureDefaultRole(context.Background(), userID)
}

func createUser(t *testing.T, db *gorm.DB, email string, verified bool) domain.User {
	t.Helper()
	row := model.User{ID: uuid.New(), Email: email, FullName: "ทดสอบ", EmailVerified: verified}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM user_roles WHERE user_id = ?`, row.ID)
		db.Exec(`DELETE FROM users WHERE id = ?`, row.ID)
	})
	return row.ToDomain()
}

// createUserWithPassword สร้างบัญชีที่ login ด้วยรหัสผ่านได้
func createUserWithPassword(
	t *testing.T, db *gorm.DB, email, passwordHash string, verified bool,
) domain.User {
	t.Helper()
	row := model.User{
		ID: uuid.New(), Email: email, FullName: "ทดสอบ",
		PasswordHash: &passwordHash, EmailVerified: verified,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM user_roles WHERE user_id = ?`, row.ID)
		db.Exec(`DELETE FROM users WHERE id = ?`, row.ID)
	})
	return row.ToDomain()
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
	env := testApp(t)
	email := newTestEmail("signup")

	resp, body := doJSON(t, env.app, "POST", "/api/v1/auth/signup", handler.SignupRequest{
		Email: email, Password: "s3cret-pass", FullName: "ทดสอบ สมัคร",
	}, "")
	t.Cleanup(func() { env.db.Exec(`DELETE FROM users WHERE email = ?`, email) })

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
	env := testApp(t)
	email := newTestEmail("dup")
	createUser(t, env.db, email, false)

	resp, _ := doJSON(t, env.app, "POST", "/api/v1/auth/signup", handler.SignupRequest{
		Email: email, Password: "whatever1", FullName: "x",
	}, "")
	if resp.StatusCode != 409 {
		t.Fatalf("status = %d ต้องการ 409 (อีเมลซ้ำ)", resp.StatusCode)
	}
}

func TestHTTP_Signup_MissingFields(t *testing.T) {
	env := testApp(t)
	resp, _ := doJSON(t, env.app, "POST", "/api/v1/auth/signup", handler.SignupRequest{Email: "", Password: ""}, "")
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400", resp.StatusCode)
	}
}

// --- Login ------------------------------------------------------------------

func TestHTTP_Login_HappyPath(t *testing.T) {
	env := testApp(t)
	email := newTestEmail("login")
	hash, _ := bcryptHashForTest("correct-pw")
	u := createUserWithPassword(t, env.db, email, hash, false)

	resp, body := doJSON(t, env.app, "POST", "/api/v1/auth/login",
		handler.LoginRequest{Email: u.Email, Password: "correct-pw"}, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200, body=%v", resp.StatusCode, body)
	}
	if tok, _ := body["token"].(string); tok == "" {
		t.Error("ต้องมี token")
	}
}

func TestHTTP_Login_WrongPassword(t *testing.T) {
	env := testApp(t)
	email := newTestEmail("wrongpw")
	hash, _ := bcryptHashForTest("correct-pw")
	createUserWithPassword(t, env.db, email, hash, false)

	resp, _ := doJSON(t, env.app, "POST", "/api/v1/auth/login",
		handler.LoginRequest{Email: email, Password: "wrong"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

func TestHTTP_Login_NonexistentEmail(t *testing.T) {
	env := testApp(t)
	resp, _ := doJSON(t, env.app, "POST", "/api/v1/auth/login",
		handler.LoginRequest{Email: newTestEmail("ghost"), Password: "x"}, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

// --- Me / lookup / keys ------------------------------------------------------

func TestHTTP_Me_ValidToken(t *testing.T) {
	env := testApp(t)
	u := createUser(t, env.db, newTestEmail("me"), false)
	tok, _ := env.issueToken(t, u)

	resp, body := doJSON(t, env.app, "GET", "/api/v1/auth/me", nil, tok)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200, body=%v", resp.StatusCode, body)
	}
	if body["email"] != u.Email {
		t.Errorf("email = %v ต้องการ %s", body["email"], u.Email)
	}
}

func TestHTTP_Me_NoToken(t *testing.T) {
	env := testApp(t)
	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/me", nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

func TestHTTP_PublicKey_ReturnsPEM(t *testing.T) {
	env := testApp(t)
	req := httptest.NewRequest("GET", "/api/v1/auth/public-key", nil)
	resp, err := env.app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !bytes.Contains(raw, []byte("PUBLIC KEY")) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestHTTP_KeyInfo(t *testing.T) {
	env := testApp(t)
	resp, body := doJSON(t, env.app, "GET", "/api/v1/auth/key-info", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body["signingKeyId"] == "" || body["signingKeyId"] == nil {
		t.Error("ต้องมี signingKeyId")
	}
}

func TestHTTP_Health(t *testing.T) {
	env := testApp(t)
	req := httptest.NewRequest("GET", "/health", nil)
	resp, _ := env.app.Test(req, -1)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// --- Admin: การเข้าถึง --------------------------------------------------------

func TestHTTP_Admin_RejectsNonSuperAdmin(t *testing.T) {
	env := testApp(t)
	u := createUser(t, env.db, newTestEmail("plain"), false)
	env.ensureDefaultRole(u.ID)
	tok, _ := env.issueToken(t, u)

	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/admin/users", nil, tok)
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d ต้องการ 403 (ไม่ใช่ SUPER_ADMIN)", resp.StatusCode)
	}
}

func mustSuperAdmin(t *testing.T, env *testEnv, email string) (domain.User, string) {
	t.Helper()
	u := createUser(t, env.db, email, true)
	if err := env.db.Exec(`INSERT INTO user_roles (user_id, role_code) VALUES (?, 'SUPER_ADMIN')`, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	tok, _ := env.issueToken(t, u)
	return u, tok
}

func TestHTTP_Admin_ListUsersAndRoles(t *testing.T) {
	env := testApp(t)
	_, tok := mustSuperAdmin(t, env, newTestEmail("admin-list"))

	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/admin/users", nil, tok)
	if resp.StatusCode != 200 {
		t.Fatalf("list users status = %d", resp.StatusCode)
	}

	req := httptest.NewRequest("GET", "/api/v1/auth/admin/roles", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp2, err := env.app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("list roles status = %d", resp2.StatusCode)
	}
}

func TestHTTP_Admin_UpdateRoles_HappyPath(t *testing.T) {
	env := testApp(t)
	_, actorTok := mustSuperAdmin(t, env, newTestEmail("actor"))
	target := createUser(t, env.db, newTestEmail("target"), false)
	env.ensureDefaultRole(target.ID)

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, body := doJSON(t, env.app, "PUT", path, handler.UpdateRolesRequest{Roles: []string{"PET_ADMIN"}}, actorTok)
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
	env := testApp(t)
	_, actorTok := mustSuperAdmin(t, env, newTestEmail("actor2"))
	target := createUser(t, env.db, newTestEmail("target2"), false)

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, _ := doJSON(t, env.app, "PUT", path, handler.UpdateRolesRequest{Roles: []string{"NOT_A_REAL_ROLE"}}, actorTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (role ไม่มีอยู่จริง)", resp.StatusCode)
	}
}

// TestHTTP_Admin_CannotRemoveOwnSuperAdmin คือเคสที่สำคัญที่สุดเคสหนึ่งของทั้งไฟล์
// ไม่เคยมีเทสต์คุ้มมาก่อนเลย — ถ้า refactor พลาดจุดนี้ SUPER_ADMIN ถอดสิทธิ์
// ตัวเองได้โดยไม่ตั้งใจ แล้วอาจไม่เหลือใครแก้กลับได้เลย
func TestHTTP_Admin_CannotRemoveOwnSuperAdmin(t *testing.T) {
	env := testApp(t)
	self, selfTok := mustSuperAdmin(t, env, newTestEmail("self-lockout"))

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", self.ID)
	resp, _ := doJSON(t, env.app, "PUT", path, handler.UpdateRolesRequest{Roles: []string{"USER"}}, selfTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (ถอด SUPER_ADMIN ของตัวเองไม่ได้)", resp.StatusCode)
	}

	roles := env.rolesForUser(self.ID)
	if !domain.HasRole(roles, domain.RoleSuperAdmin) {
		t.Fatal("🚨 SUPER_ADMIN หลุดจาก role ของตัวเองทั้งที่ควรถูกบล็อก")
	}
}

// TestHTTP_Admin_CannotRemoveLastSuperAdmin อีกเคสที่ไม่เคยมีเทสต์คุ้ม คนละ
// เคสกับ self-lockout: actor ที่ "ไม่ใช่" target เป็นคนพยายามถอด SUPER_ADMIN
// ของคนสุดท้ายที่เหลือในระบบ
//
// การตั้งฉากนี้ยากกว่าที่คิด: ต้อง RequireRole(SUPER_ADMIN) ผ่านก่อนถึงจะเรียก
// endpoint นี้ได้เลย ถ้า SUPER_ADMIN ในระบบ (ตาม user_roles) เหลือแค่คนเดียว
// คนที่เรียกได้ก็มีแต่คนๆ นั้น ทำให้ actor กับ target จะเป็นคนเดียวกันเสมอ
// (กลายเป็น self-lockout ไปโดยปริยาย ไม่ใช่เคสที่ต้องการ)
//
// ทางเดียวที่ actor ≠ target เกิดขึ้นได้จริงคือผ่านทางผ่านสำรองใน RequireRole
// (isBootstrapAdminFromToken) — บัญชีที่อยู่ใน bootstrap_admins และยืนยันอีเมล
// แล้วผ่าน middleware ได้โดยไม่ต้องมี role SUPER_ADMIN ใน user_roles เลย
// สถานการณ์นี้ไม่ได้แต่งขึ้นลอยๆ แต่เป็นทางที่ระบบออกแบบไว้จริงสำหรับช่วง
// เปลี่ยนผ่าน (ดูคอมเมนต์ RequireRole ใน internal/adapter/handler/middleware.go)
func TestHTTP_Admin_CannotRemoveLastSuperAdmin(t *testing.T) {
	env := testApp(t)

	// target คือ SUPER_ADMIN ตัวจริงหนึ่งเดียวที่มีอยู่ในเทสต์นี้ (DB ทดสอบ
	// แยกจาก production จึงเริ่มจากศูนย์ ไม่มี SUPER_ADMIN เดิมมาปน)
	target, _ := mustSuperAdmin(t, env, newTestEmail("last-admin-target"))

	// actor ไม่มี role SUPER_ADMIN เลย แต่ยืนยันอีเมลแล้วและอยู่ใน
	// bootstrap_admins จึงผ่าน RequireRole ได้ทางสำรอง
	actorEmail := newTestEmail("bootstrap-actor")
	actor := createUser(t, env.db, actorEmail, true)
	if err := env.db.Exec(`INSERT INTO bootstrap_admins (email, role_code, note) VALUES (?, 'SUPER_ADMIN', 'test')`,
		actorEmail).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.db.Exec(`DELETE FROM bootstrap_admins WHERE email = ?`, actorEmail) })
	env.ensureDefaultRole(actor.ID) // ให้มี role USER เฉยๆ ไม่มี SUPER_ADMIN

	// ⚠️ ห้ามให้ token ใบนี้ผ่าน reconcileBootstrapAdmin — ขั้นตอนนั้นจะ grant
	// SUPER_ADMIN ให้ actor จริงใน user_roles ทันที (เพราะ email_verified=true
	// และอยู่ใน bootstrap_admins) ทำให้ระบบมี SUPER_ADMIN ตัวจริง 2 คนแทนที่
	// จะเป็น 1 แล้วเทสต์นี้จะไม่ได้ทดสอบ "ทางผ่านสำรอง" เลย (เจอมาแล้วจาก
	// การรันจริงรอบแรก — ไม่ใช่บั๊กของระบบ แต่เป็นจุดบกพร่องของการตั้งฉากเทสต์)
	//
	// เซ็น token ตรงๆ ด้วย token service มอบแค่ role USER ให้ตรงกับโทเคนเก่า
	// ที่ออกก่อนมี reconcile logic จริงๆ (ซึ่งเป็นสถานการณ์ที่ทางผ่านสำรองนี้
	// ถูกออกแบบมาให้รองรับ)
	actorTok, err := env.tokens.Issue(actor, []string{domain.RoleUser})
	if err != nil {
		t.Fatal(err)
	}

	path := fmt.Sprintf("/api/v1/auth/admin/users/%s/roles", target.ID)
	resp, _ := doJSON(t, env.app, "PUT", path, handler.UpdateRolesRequest{Roles: []string{"USER"}}, actorTok)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d ต้องการ 400 (จะเหลือ SUPER_ADMIN ศูนย์คนในระบบ)", resp.StatusCode)
	}

	if !domain.HasRole(env.rolesForUser(target.ID), domain.RoleSuperAdmin) {
		t.Fatal("🚨 SUPER_ADMIN คนสุดท้ายถูกถอดสิทธิ์ทั้งที่ควรถูกบล็อก")
	}
}

// bcryptHashForTest ใช้ cost ต่ำกว่า production (10) เพื่อให้เทสต์เร็วขึ้น
// ไม่กระทบพฤติกรรมที่ทดสอบเพราะ Login เทียบด้วย bcrypt.CompareHashAndPassword
// ซึ่งอ่าน cost จากตัว hash เองอยู่แล้ว ไม่ต้องรู้ล่วงหน้า
func bcryptHashForTest(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 4)
	return string(hash), err
}
