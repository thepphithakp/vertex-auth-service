//go:build integration

package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/domain"
)

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

func TestRolesForUser_DefaultsToUser(t *testing.T) {
	db := openTestDB(t)
	repo := NewGORMRoleRepository(db)
	ctx := context.Background()

	u := createUser(t, db, "norole-"+uuid.NewString()[:8]+"@example.com", false)

	roles := repo.RolesForUser(ctx, u.ID)
	if len(roles) != 1 || roles[0] != domain.RoleUser {
		t.Fatalf("roles = %v ต้องการ [USER]", roles)
	}

	repo.EnsureDefaultRole(ctx, u.ID)
	if roles := repo.RolesForUser(ctx, u.ID); len(roles) != 1 || roles[0] != domain.RoleUser {
		t.Fatalf("roles = %v", roles)
	}
}

func TestCountSuperAdmins(t *testing.T) {
	db := openTestDB(t)
	repo := NewGORMRoleRepository(db)
	ctx := context.Background()

	before, err := repo.CountSuperAdmins(ctx)
	if err != nil {
		t.Fatal(err)
	}

	u := createUser(t, db, "sa-"+uuid.NewString()[:8]+"@example.com", true)
	db.Exec(`INSERT INTO user_roles (user_id, role_code) VALUES (?, 'SUPER_ADMIN')`, u.ID)

	after, _ := repo.CountSuperAdmins(ctx)
	if after != before+1 {
		t.Fatalf("นับได้ %d ต้องการ %d", after, before+1)
	}
}
