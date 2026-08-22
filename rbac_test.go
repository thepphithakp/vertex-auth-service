package main

import (
	"testing"
)

func TestRolesFromClaims(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]interface{}
		want   []string
	}{
		{
			// สำคัญที่สุด: token ที่ออกก่อนเฟสนี้ต้องยังใช้งานได้
			name:   "token เดิมที่ไม่มี roles → USER",
			claims: map[string]interface{}{"sub": "x"},
			want:   []string{RoleUser},
		},
		{
			name:   "roles ว่าง → USER",
			claims: map[string]interface{}{"roles": []interface{}{}},
			want:   []string{RoleUser},
		},
		{
			name:   "roles ปกติ",
			claims: map[string]interface{}{"roles": []interface{}{"SUPER_ADMIN", "USER"}},
			want:   []string{"SUPER_ADMIN", "USER"},
		},
		{
			name:   "ค่าที่ไม่ใช่ string ถูกทิ้ง",
			claims: map[string]interface{}{"roles": []interface{}{"USER", 42, nil, ""}},
			want:   []string{"USER"},
		},
		{
			name:   "roles ผิดชนิด → USER",
			claims: map[string]interface{}{"roles": "SUPER_ADMIN"},
			want:   []string{RoleUser},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rolesFromClaims(tc.claims)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}

func TestHasRole(t *testing.T) {
	roles := []string{RoleUser, RolePetAdmin}
	if !hasRole(roles, RolePetAdmin) {
		t.Fatal("ต้องเจอ PET_ADMIN")
	}
	if hasRole(roles, RoleSuperAdmin) {
		t.Fatal("ไม่ควรเจอ SUPER_ADMIN")
	}
	if hasRole(nil, RoleUser) {
		t.Fatal("slice ว่างต้องไม่เจออะไร")
	}
}
