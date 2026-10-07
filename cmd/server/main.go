// Command server คือ entrypoint ของ auth-service
//
// หน้าที่เหลือแค่ลำดับการ start: ตั้ง logger, อ่าน config, ต่อฐานข้อมูล,
// ประกอบ app แล้วรับ request — การประกอบชั้นต่างๆ อยู่ที่ internal/bootstrap
package main

import (
	"log"

	"vertex-auth-service/internal/bootstrap"
	"vertex-auth-service/internal/config"
	"vertex-auth-service/pkg/middleware"
)

// หมายเหตุ: เคยมี initAppleJWKS() ที่ดึง JWKS ของ Apple ตอน start
//
// ลบออกเพราะไม่มี endpoint ไหนตรวจ token ของ Apple เลย (มีแค่ /google
// ซึ่งใช้ idtoken.Validate) ค่าที่ดึงมาถูกเขียนลงตัวแปร global แล้วไม่เคยถูกอ่าน
// แต่มันทำ network call ตอน start และ log.Fatalf ถ้าล้ม
// ผลคือ auth-service สตาร์ตไม่ขึ้นเลยถ้า appleid.apple.com เข้าไม่ได้
// โดยไม่ได้อะไรตอบแทน

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("ตั้งค่าไม่ถูกต้อง: ", err)
	}

	// ต้องเรียกก่อนอะไรทั้งหมด ไม่งั้น slog ใช้ text handler ของ Go
	// เป็น default แล้ว NewAccessLog ที่เขียนด้วย slog จะไม่ได้เป็น JSON
	middleware.SetupLogger(cfg.Log.Level)

	db := bootstrap.NewDB(cfg.DB)
	bootstrap.AssertSchemaReady(db)

	app, err := bootstrap.NewApp(db, cfg)
	if err != nil {
		log.Fatal("ประกอบ app ไม่สำเร็จ: ", err)
	}

	log.Fatal(app.Listen(":" + cfg.Port))
}
