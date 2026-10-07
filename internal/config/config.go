// Package config รวมการอ่านค่าตั้งค่าจาก environment ไว้ที่เดียว
//
// เดิม os.Getenv กระจายอยู่สามที่: config.go (JWT_*), main.go initDB
// (DATABASE_URL) และ main.go main() (LOG_LEVEL)
package config

import (
	"fmt"
	"os"
	"strings"
)

// DefaultPort คือพอร์ตที่ service รับ request
//
// 🔸 ไม่ได้อ่านจาก env โดยตั้งใจ — main.go เดิม hardcode ":4000" ไว้
//
//	helm chart ตั้ง PORT=4000 ให้อยู่แล้วแต่โค้ดไม่เคยอ่าน
//	การเริ่มอ่านตอนนี้เปลี่ยนพฤติกรรมของ deploy ซึ่งอยู่นอกขอบเขตรอบนี้
const DefaultPort = "4000"

// DSN ที่ hardcode ไว้ เป็นพฤติกรรมเดิมของ initDB
//
// 🔸 มีรหัสผ่านอยู่ในโค้ด และชี้ไป namespace default ไม่ใช่ vertex
//
//	ควรบังคับให้ตั้ง DATABASE_URL แล้วเอาสองค่านี้ออก แต่การเปลี่ยนตอนนี้
//	ทำให้ทั้ง deploy และ local dev ที่พึ่ง fallback นี้พัง — คงไว้ทั้งคู่
const (
	// ClusterDSN ใช้เมื่อไม่ได้ตั้ง DATABASE_URL
	ClusterDSN = "host=vertex-postgres-postgresql.default.svc.cluster.local " +
		"user=postgres password=password dbname=auth port=5432 sslmode=disable"

	// LocalDSN ใช้เมื่อต่อด้วย DSN ใบแรกไม่ติด
	LocalDSN = "host=localhost user=postgres password=password dbname=auth port=5432 sslmode=disable"
)

type Config struct {
	Port string

	DB  DBConfig
	JWT JWTConfig
	Log LogConfig
}

type DBConfig struct {
	// URL คือค่าจาก DATABASE_URL — ว่างได้ แล้วจะใช้ ClusterDSN
	URL string
}

// DSN คืน DSN ใบแรกที่จะลองต่อ
func (d DBConfig) DSN() string {
	if d.URL != "" {
		return d.URL
	}
	return ClusterDSN
}

// FallbackDSN คืน DSN ใบที่สอง ใช้เมื่อใบแรกต่อไม่ติด
//
// เป็น localhost เสมอ ไม่ว่าใบแรกจะมาจาก DATABASE_URL หรือ ClusterDSN
// (พฤติกรรมเดิมของ initDB)
func (d DBConfig) FallbackDSN() string {
	return LocalDSN
}

type JWTConfig struct {
	// PrivateKeyPEM มาก่อนไฟล์ keys/private.pem ใน image เสมอ
	//
	// 🔴 สำคัญ: keys/private.pem ถูก commit เข้า git ตั้งแต่ commit แรก
	//    key ตัวนั้นต้องถือว่ารั่วแล้ว และ token ที่เซ็นด้วยมันปลอมได้ทุกใบ
	//    การใส่ทางให้อ่านจาก env คือเงื่อนไขที่ทำให้ rotate ได้จริง
	PrivateKeyPEM string

	// PublicKeysPEM รับ PEM หลายบล็อกต่อกัน ใช้ระหว่าง rotate key
	// มาก่อน PublicKeyPEM แล้วค่อย fallback ไปไฟล์ keys/public.pem
	PublicKeysPEM string
	PublicKeyPEM  string

	// Issuer / Audience ใส่ลง token เมื่อไม่ว่าง
	//
	// ⚠️ ปล่อยแบบ 2 เฟส: ให้ auth-service เริ่มออกก่อน รออย่างน้อย 72 ชั่วโมง
	//    (เท่าอายุ token เดิม) แล้วค่อยเปิดการตรวจที่ pet-service
	//    ถ้าเปิดตรวจก่อน token ที่ผู้ใช้ถืออยู่จะใช้ไม่ได้ทันทีทั้งระบบ
	Issuer   string
	Audience string
}

type LogConfig struct {
	Level string
}

// Load อ่านค่าจาก environment พร้อม default ที่ตรงกับพฤติกรรมเดิมทุกตัว
func Load() (Config, error) {
	cfg := Config{
		Port: DefaultPort,
		DB: DBConfig{
			URL: os.Getenv("DATABASE_URL"),
		},
		JWT: JWTConfig{
			PrivateKeyPEM: os.Getenv("JWT_PRIVATE_KEY"),
			PublicKeysPEM: os.Getenv("JWT_PUBLIC_KEYS"),
			PublicKeyPEM:  os.Getenv("JWT_PUBLIC_KEY"),
			Issuer:        os.Getenv("JWT_ISSUER"),
			Audience:      os.Getenv("JWT_AUDIENCE"),
		},
		Log: LogConfig{
			// ว่างได้ — SetupLogger ถือว่าเป็น info
			Level: os.Getenv("LOG_LEVEL"),
		},
	}
	return cfg, cfg.Validate()
}

// Validate ตรวจค่าที่ขาดไม่ได้ เพื่อให้ล้มตั้งแต่ตอน boot พร้อมข้อความชัดเจน
// แทนที่จะไปพังตอน query แรกหรือตอน login แรก
//
// 🔸 ตอนนี้ยังไม่มีค่าไหนบังคับ เพราะทุกตัวมี fallback ที่ production ใช้อยู่จริง:
//
//	DATABASE_URL ว่าง → ClusterDSN, JWT_* ว่าง → อ่านไฟล์ใน image
//	การบังคับตัวใดตัวหนึ่งตอนนี้จะทำให้ที่ deploy อยู่แล้วสตาร์ตไม่ขึ้น
//
//	ฟังก์ชันนี้มีไว้ให้จุดที่เพิ่มเงื่อนไขอยู่ที่เดียว — เพิ่มชื่อ env กับค่า
//	ลงใน required แล้วข้อความจะออกมารูปแบบเดียวกับ pet-service/event-service
func (c Config) Validate() error {
	required := map[string]string{
		// ยังไม่มี — ดูเหตุผลในคอมเมนต์ข้างบน
	}

	var missing []string
	for name, v := range required {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("ไม่ได้ตั้งค่า environment ที่จำเป็น: %s", strings.Join(missing, ", "))
	}
	return nil
}
