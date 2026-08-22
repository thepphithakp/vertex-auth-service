package main

import "os"

// ค่าตั้งค่าที่อ่านจาก environment
//
// 🔸 auth-service ยังอ่าน env กระจายอยู่หลายที่ (initDB, initRSAKeys)
//
//	การรวมมาไว้ที่เดียวทั้งหมดเป็นงานของ Phase 9
//	ตรงนี้เพิ่มเฉพาะค่าที่เฟสนี้ต้องใช้
var (
	// jwtIssuer / jwtAudience ใส่ลง token เมื่อไม่ว่าง
	//
	// ⚠️ ปล่อยแบบ 2 เฟส: ให้ auth-service เริ่มออกก่อน รออย่างน้อย 72 ชั่วโมง
	//    (เท่าอายุ token เดิม) แล้วค่อยเปิดการตรวจที่ pet-service
	//    ถ้าเปิดตรวจก่อน token ที่ผู้ใช้ถืออยู่จะใช้ไม่ได้ทันทีทั้งระบบ
	jwtIssuer   = os.Getenv("JWT_ISSUER")
	jwtAudience = os.Getenv("JWT_AUDIENCE")

	// privateKeySource รองรับการ rotate key ผ่าน Secret โดยไม่ต้อง rebuild image
	//
	// 🔴 สำคัญ: keys/private.pem ถูก commit เข้า git ตั้งแต่ commit แรก
	//    key ตัวนั้นต้องถือว่ารั่วแล้ว และ token ที่เซ็นด้วยมันปลอมได้ทุกใบ
	//    การใส่ทางให้อ่านจาก env คือเงื่อนไขที่ทำให้ rotate ได้จริง
	jwtPrivateKeyPEM = os.Getenv("JWT_PRIVATE_KEY")
	jwtPublicKeyPEM  = os.Getenv("JWT_PUBLIC_KEY")
)
