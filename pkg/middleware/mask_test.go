package middleware

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMaskBody ยืนยันว่าค่าจริงของ credential ไม่หลุดเข้า log
//
// นี่คือ test ที่สำคัญที่สุดของใบนี้ (VT-71) — auth-service จัดการ
// password และ token โดยตรง พลาดจุดนี้จุดเดียวคือรหัสผ่านผู้ใช้จริง
// ไหลเข้า Elasticsearch ทันทีที่ login ล้มเหลว (ซึ่งเกิดบ่อยกว่าที่คิด
// เพราะพิมพ์รหัสผ่านผิดเป็นเรื่องปกติของผู้ใช้จริง)
func TestMaskBody(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		mustHide   []string
		mustRemain []string
	}{
		{
			name:       "login request จริง",
			in:         `{"email":"user@example.com","password":"hunter2"}`,
			mustHide:   []string{"user@example.com", "hunter2"},
			mustRemain: []string{},
		},
		{
			name:       "signup request มี fullName ที่ไม่ต้องปิด",
			in:         `{"email":"a@b.com","password":"x","fullName":"สมชาย ใจดี"}`,
			mustHide:   []string{"a@b.com", "x"},
			mustRemain: []string{"สมชาย ใจดี"},
		},
		{
			name:     "google login มี idToken",
			in:       `{"idToken":"eyJhbGciOi...","email":"g@x.com","fullName":"A"}`,
			mustHide: []string{"eyJhbGciOi...", "g@x.com"},
		},
		{
			name:     "ตัวพิมพ์ใหญ่เล็กต่างกัน",
			in:       `{"Password":"p","PASSWORDHASH":"h"}`,
			mustHide: []string{"p", "h"},
		},
		{
			name:     "ฟิลด์ซ้อนอยู่ใน object ชั้นใน",
			in:       `{"user":{"email":"nested@x.com","password":"q"}}`,
			mustHide: []string{"nested@x.com", "q"},
		},
		{
			name:     "ฟิลด์ซ้อนอยู่ใน array",
			in:       `{"users":[{"email":"arr@x.com"}]}`,
			mustHide: []string{"arr@x.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var check any
			if err := json.Unmarshal([]byte(tc.in), &check); err != nil {
				t.Fatalf("input ไม่ใช่ JSON ที่ถูกต้อง: %v", err)
			}

			got := maskBody([]byte(tc.in))

			for _, hidden := range tc.mustHide {
				if strings.Contains(got, hidden) {
					t.Errorf("ค่าที่ต้องปิดหลุดออกมา %q อยู่ใน output: %s", hidden, got)
				}
			}
			for _, remain := range tc.mustRemain {
				if !strings.Contains(got, remain) {
					t.Errorf("ค่าที่ควรเหลืออยู่หายไป %q ไม่พบใน output: %s", remain, got)
				}
			}
		})
	}
}

func TestMaskBody_NotJSON(t *testing.T) {
	// อินพุตที่ไม่ใช่ JSON
	got := maskBody([]byte("not json at all"))
	if got != "[ไม่ใช่ JSON]" {
		t.Errorf("ควรได้ [ไม่ใช่ JSON] แต่ได้ %q", got)
	}
}

func TestMaskBody_Empty(t *testing.T) {
	// body ว่าง
	if got := maskBody(nil); got != "" {
		t.Errorf("body ว่างควรได้ string ว่าง แต่ได้ %q", got)
	}
}
