// Package handler คือ input adapter ฝั่ง HTTP (Fiber)
//
// หน้าที่มีแค่สองอย่าง: แปลง request เป็น input ของ use case
// และแปลง error ของ use case เป็นสถานะ HTTP — ไม่มีกฎของธุรกิจที่นี่
package handler

import "github.com/gofiber/fiber/v2"

// SendError ตอบ error ตามรูปแบบเดิม {error, requestId}
//
// export เพราะทั้งสาม handler, middleware และ ErrorHandler ของ Fiber
// ที่ประกอบใน internal/bootstrap ใช้ตัวเดียวกัน — รูปแบบ response
// ของ error ต้องเหมือนกันทุกเส้นทาง รวมถึง 404 ที่ไม่ตรง route ไหนเลย
func SendError(c *fiber.Ctx, status int, message string) error {
	reqID := c.Get("X-Request-Id")
	if reqID == "" {
		if val, ok := c.Locals("requestid").(string); ok {
			reqID = val
		}
	}
	return c.Status(status).JSON(fiber.Map{
		"error":     message,
		"requestId": reqID,
	})
}

// bearerToken ดึง token จาก header Authorization
//
// ตรวจความยาวและ prefix แบบเดียวกับโค้ดเดิมทุกตัวอักษร
func bearerToken(c *fiber.Ctx) (string, bool) {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", false
	}
	return authHeader[7:], true
}
