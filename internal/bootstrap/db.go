// Package bootstrap คือ composition root — ที่เดียวที่รู้จักทุกชั้นพร้อมกัน
//
// ต่างจากชั้น adapter: แพ็กเกจนี้เรียก log.Fatal ได้ เพราะการตัดสินว่า
// ปัญหาตอน start ร้ายแรงพอจะล้มทั้ง process ไหม เป็นหน้าที่ของที่นี่
package bootstrap

import (
	"context"
	"log"
	"strconv"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/repository"
	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/config"
)

// NewDB ต่อฐานข้อมูลตาม DSN ใบแรก แล้วลอง localhost ถ้าต่อไม่ติด
func NewDB(cfg config.DBConfig) *gorm.DB {
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{})
	if err != nil {
		log.Println("WARNING: Failed to connect to DB, retrying with localhost...")
		db, err = gorm.Open(postgres.Open(cfg.FallbackDSN()), &gorm.Config{})
		if err != nil {
			log.Fatal("Failed to connect to database: ", err)
		}
	}
	return db
}

// requiredSchemaVersion คือเวอร์ชัน migration ต่ำสุดที่โค้ดชุดนี้ทำงานได้
//
// ⚠️ ต้องเพิ่มค่านี้ทุกครั้งที่เพิ่ม V__ ใหม่ที่โค้ดพึ่งพา
// และห้ามเพิ่มถ้าโค้ดยังไม่ได้ใช้ schema นั้น (จะทำให้ deploy ไม่ผ่านโดยไม่จำเป็น)
const requiredSchemaVersion = 3

// AssertSchemaReady มาแทน AutoMigrate
//
// AutoMigrate ถูกถอดออกแล้ว — schema ทั้งหมดจัดการด้วย Flyway
// (repo vertex-migrations, schema auth)
//
// เหตุผลที่เลิกใช้:
//   - รันทุก pod ที่ start → replica ที่ 2, 3 ต้องรอ lock ก่อนถึงจะขึ้น
//   - ลบ/rename column ไม่ได้ ทำ data migration ไม่ได้ seed ข้อมูลไม่ได้
//   - review ใน PR ไม่ได้ และ schema จริงค่อยๆ ห่างจากสิ่งที่ควบคุมได้
//
// Flyway Job รันก่อน pod ใหม่ขึ้น หน้าที่ของแอปเหลือแค่ยืนยันว่า migration
// รันครบแล้ว แล้วล้มทันทีถ้ายัง — ปลอดภัยกว่าปล่อยให้ขึ้นแล้วไปพังตอน login แรก
func AssertSchemaReady(db *gorm.DB) {
	var version string
	err := db.Raw(`
		SELECT version FROM flyway_schema_history
		WHERE success AND version IS NOT NULL
		ORDER BY installed_rank DESC LIMIT 1`).Scan(&version).Error
	if err != nil {
		log.Fatalf("อ่านตาราง flyway_schema_history ไม่ได้ — migration อาจยังไม่เคยรัน "+
			"(ตรวจ search_path และ Flyway Job): %v", err)
	}
	major, convErr := strconv.Atoi(strings.SplitN(strings.TrimSpace(version), ".", 2)[0])
	if convErr != nil {
		log.Fatalf("อ่าน schema version %q ไม่ได้: %v", version, convErr)
	}
	if major < requiredSchemaVersion {
		log.Fatalf("ฐานข้อมูลอยู่ที่ V%s แต่โค้ดต้องการ V%d — รัน migration ก่อน",
			version, requiredSchemaVersion)
	}
	log.Printf("schema version V%s (ต้องการอย่างน้อย V%d) ✓", version, requiredSchemaVersion)

	required := []string{"roles", "user_roles", "bootstrap_admins"}
	for _, table := range required {
		if !db.Migrator().HasTable(table) {
			log.Fatalf("ไม่พบตาราง %q — ยังไม่ได้รัน Flyway migration (ดู db/migration)", table)
		}
	}
	if !db.Migrator().HasColumn(&model.User{}, "email_verified") {
		log.Fatal("users ไม่มี column email_verified — ยังไม่ได้รัน Flyway migration")
	}

	// นับ SUPER_ADMIN เพื่อ log เท่านั้น ไม่ใช่เงื่อนไขให้ล้ม
	n, err := repository.NewGORMRoleRepository(db).CountSuperAdmins(context.Background())
	if err != nil {
		log.Printf("นับ SUPER_ADMIN ไม่สำเร็จ: %v", err)
		return
	}
	if n == 0 {
		log.Println("⚠️  ยังไม่มี SUPER_ADMIN ในระบบ — backoffice จะเข้าหน้า admin ไม่ได้")
		log.Println("    ให้บัญชีที่อยู่ใน bootstrap_admins login ผ่าน Google หนึ่งครั้ง")
	} else {
		log.Printf("🔐 SUPER_ADMIN ในระบบ: %d คน", n)
	}
}
