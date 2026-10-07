//go:build integration

package bootstrap

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
)

// ไฟล์นี้คุม endpoint สองตัวที่ pin เดิมไม่ได้แตะเลย: GET /lookup กับ
// GET /users (ไม่ใช่ /admin/users) ทั้งคู่ถูกเขียนใหม่ตอนย้ายเป็น hexagonal
// จึงควรมีอะไรยืนยันรูปร่าง response กับการป้องกันของมันไว้
//
// ไม่ใช่ฟีเจอร์ใหม่ — ยืนยันพฤติกรรมเดิมที่ lookupUser และ getAllUsers
// ของ main.go ทำอยู่

func TestHTTP_Lookup_FindsUserByEmail(t *testing.T) {
	env := testApp(t)
	u := createUser(t, env.db, newTestEmail("lookup"), false)
	tok, _ := env.issueToken(t, u)

	resp, body := doJSON(t, env.app, "GET", "/api/v1/auth/lookup?email="+u.Email, nil, tok)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200, body=%v", resp.StatusCode, body)
	}
	if body["email"] != u.Email {
		t.Errorf("email = %v ต้องการ %s", body["email"], u.Email)
	}
	if body["id"] != u.ID.String() {
		t.Errorf("id = %v ต้องการ %s", body["id"], u.ID)
	}
	// ห้ามมี hash รหัสผ่านหรือสถานะการยืนยันอีเมลหลุดออกไป
	for _, k := range []string{"passwordHash", "PasswordHash", "emailVerified"} {
		if _, ok := body[k]; ok {
			t.Errorf("response ไม่ควรมีฟิลด์ %q", k)
		}
	}
}

func TestHTTP_Lookup_UnknownEmail(t *testing.T) {
	env := testApp(t)
	u := createUser(t, env.db, newTestEmail("lookup-404"), false)
	tok, _ := env.issueToken(t, u)

	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/lookup?email="+newTestEmail("ghost"), nil, tok)
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d ต้องการ 404", resp.StatusCode)
	}
}

func TestHTTP_Lookup_RequiresAuth(t *testing.T) {
	env := testApp(t)
	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/lookup?email=x@example.com", nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401", resp.StatusCode)
	}
}

// TestHTTP_ListUsers_RequiresSuperAdmin คุมช่องโหว่ที่เคยถูกปิดไว้
//
// 🔴 endpoint นี้เคยเปิดให้ผู้ใช้ที่ login แล้วทุกคนดึงอีเมลของทุกคนในระบบได้
//
//	ถ้า refactor ทำ middleware หลุดจาก route นี้ ช่องโหว่เดิมจะกลับมาทันที
func TestHTTP_ListUsers_RequiresSuperAdmin(t *testing.T) {
	env := testApp(t)
	u := createUser(t, env.db, newTestEmail("plain-list"), false)
	env.ensureDefaultRole(u.ID)
	tok, _ := env.issueToken(t, u)

	resp, _ := doJSON(t, env.app, "GET", "/api/v1/auth/users", nil, tok)
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d ต้องการ 403 (ไม่ใช่ SUPER_ADMIN)", resp.StatusCode)
	}

	resp2, _ := doJSON(t, env.app, "GET", "/api/v1/auth/users", nil, "")
	if resp2.StatusCode != 401 {
		t.Fatalf("status = %d ต้องการ 401 (ไม่มี token)", resp2.StatusCode)
	}
}

// TestHTTP_ListUsers_ShapeHasNoSecrets ยืนยันว่า response ยังเป็น
// {id, email, fullName} เหมือน SafeUser เดิม ไม่มี hash รหัสผ่านติดไปด้วย
func TestHTTP_ListUsers_ShapeHasNoSecrets(t *testing.T) {
	env := testApp(t)
	target := createUser(t, env.db, newTestEmail("listed"), false)
	_, tok := mustSuperAdmin(t, env, newTestEmail("list-admin"))

	req := httptest.NewRequest("GET", "/api/v1/auth/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := env.app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d ต้องการ 200", resp.StatusCode)
	}

	raw, _ := io.ReadAll(resp.Body)
	var users []map[string]any
	if err := json.Unmarshal(raw, &users); err != nil {
		t.Fatalf("response ต้องเป็น array ของ object: %v (body=%s)", err, raw)
	}

	found := false
	for _, u := range users {
		if u["email"] == target.Email {
			found = true
		}
		// ทุกแถวต้องมีแค่สามฟิลด์นี้
		if len(u) != 3 {
			t.Fatalf("แถวมี %d ฟิลด์ ต้องการ 3 (id, email, fullName): %v", len(u), u)
		}
		for _, k := range []string{"id", "email", "fullName"} {
			if _, ok := u[k]; !ok {
				t.Errorf("แถวขาดฟิลด์ %q: %v", k, u)
			}
		}
	}
	if !found {
		t.Errorf("ไม่พบ %s ในรายการ", target.Email)
	}

	// กันเทสต์ผ่านเพราะ array ว่าง
	if len(users) == 0 {
		t.Fatal("รายการว่าง — เทสต์นี้ไม่ได้ยืนยันอะไรเลย")
	}
}
