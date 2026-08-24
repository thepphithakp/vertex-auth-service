package middleware

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
)

// maxBodyLogBytes จำกัดขนาด body ที่เขียนลง log
// เท่ากับค่า default ของ vertex-pet-service เพื่อความสม่ำเสมอข้าม service
const maxBodyLogBytes = 4 << 10 // 4KB

// SetupLogger ตั้ง global logger เป็น JSON
//
// แทนที่ fiber/middleware/logger ตัวเดิมที่ใช้ format string ตายตัว
// ("${time}" ของ Fiber ให้แค่เวลาไม่มีวันที่ — เป็นสาเหตุหนึ่งของ VT-60)
// สลับมาใช้ log/slog เหมือน pet-service และ event-service เพื่อให้
// รูปแบบ log สม่ำเสมอกันทั้งสาม service และ timestamp มีวันที่ + offset
func SetupLogger(level string) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

// NewAccessLog เขียน access log หนึ่งบรรทัดต่อหนึ่ง request
//
// 🔴 log body เฉพาะตอน error (status >= 400) เท่านั้น ไม่ใช่ทุก request
//
// ค่านี้สำคัญที่สุดสำหรับ auth-service เพราะจัดการ credential โดยตรง
// เปิด log body ทุก request (รวมตอน 200) จะทำให้อีเมลผู้ใช้ไหลเข้า log
// ทุกครั้งที่ login สำเร็จ โดยที่ไม่มีประโยชน์ต่อการ investigate เลย
// เพราะตอนสำเร็จไม่มีอะไรต้องสืบ — จำกัดไว้เฉพาะตอนพังเท่านั้น
// (ปัญหาเดียวกับที่ทำให้เกิดความเข้าใจผิดใน VT-69)
//
// ผ่าน maskBody ก่อนเสมอ ตัดค่า password/token/email ออกแม้ตอน error
func NewAccessLog() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()

		// 🔴 อ่าน c.Response().StatusCode() ตรงๆ ไม่พอเมื่อ handler
		// return error object แทนที่จะเรียก c.Status().JSON() เอง —
		// ErrorHandler กลางทำงาน "หลังจาก" middleware chain นี้ unwind
		// ไปแล้ว ไม่ใช่ระหว่าง c.Next() (สำคัญมากสำหรับ route ที่ไม่
		// match เลย ซึ่งเป็นสาเหตุที่ทำให้ VT-69 เข้าใจผิดว่า 500)
		status := c.Response().StatusCode()
		if err != nil {
			status = resolveErrStatus(err)
		}

		// endpoint คือ route pattern ที่ลงทะเบียนไว้ (รวม group prefix
		// เช่น "/api/v1/auth/login") ไม่ใช่แค่ path ที่ผู้ใช้ยิงมา
		// ถ้าไม่ match route ไหนเลย c.Route() จะเป็น nil จึง fallback
		// ไปที่ c.Path() แทน — กรณีนี้เกิดขึ้นบ่อยกว่าที่คิดเพราะเป็น
		// ทาง distinguish 404 (ไม่ match route) ออกจาก endpoint จริงที่ error
		endpoint := c.Path()
		if r := c.Route(); r != nil && r.Path != "" {
			endpoint = r.Path
		}

		attrs := []any{
			// เวลาที่เกิดจริง มีวันที่และ offset ครบ ต่างจาก
			// ${time} ของ Fiber logger เดิมที่ให้แค่ HH:MM:SS
			slog.String("time", start.Format(time.RFC3339)),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.String("endpoint", endpoint),
			slog.Int("status", status),
			slog.Duration("latency", time.Since(start)),
			slog.String("requestId", c.Get(HeaderRequestID)),
			slog.String("ip", c.IP()),
		}

		if status >= 400 {
			if b := truncate(maskBody(c.Body()), maxBodyLogBytes); b != "" {
				attrs = append(attrs, slog.String("req_body", b))
			}
			if b := truncate(maskBody(c.Response().Body()), maxBodyLogBytes); b != "" {
				attrs = append(attrs, slog.String("res_body", b))
			}
		}

		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}
		slog.LogAttrs(c.UserContext(), level, "http_request", toAttrs(attrs)...)

		return err
	}
}

func toAttrs(vals []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(vals))
	for _, v := range vals {
		if a, ok := v.(slog.Attr); ok {
			out = append(out, a)
		}
	}
	return out
}

// resolveErrStatus เดา HTTP status ที่ ErrorHandler จะกำหนดให้ error นี้
// ต้องตรงกับ logic ใน main.go ทุกประการ
func resolveErrStatus(err error) int {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	return fiber.StatusInternalServerError
}
