package bootstrap

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/google"
	"vertex-auth-service/internal/adapter/handler"
	"vertex-auth-service/internal/adapter/password"
	"vertex-auth-service/internal/adapter/repository"
	"vertex-auth-service/internal/adapter/token"
	"vertex-auth-service/internal/application"
	"vertex-auth-service/internal/config"
	"vertex-auth-service/internal/domain"
	"vertex-auth-service/pkg/middleware"
)

// NewApp ประกอบทุกชั้นเข้าด้วยกันแล้วคืน Fiber app ที่พร้อมรับ request
//
// มาแทน buildApp() ของ main.go เดิม — ลำดับการผูก middleware และ route
// เหมือนเดิมทุกบรรทัด เปลี่ยนแค่ว่า dependency ถูกส่งเข้าไปแทนการอ่าน global
//
// คืน error เมื่อโหลดคีย์ไม่สำเร็จ — ผู้เรียก (cmd/server) ตัดสินว่าจะล้มไหม
func NewApp(db *gorm.DB, cfg config.Config) (*fiber.App, error) {
	// --- output adapter ---
	userRepo := repository.NewGORMUserRepository(db)
	oauthRepo := repository.NewGORMOAuthIdentityRepository(db)
	roleRepo := repository.NewGORMRoleRepository(db)

	tokenService, err := token.NewJWTTokenService(token.Config{
		PrivateKeyPEM: cfg.JWT.PrivateKeyPEM,
		PublicKeysPEM: cfg.JWT.PublicKeysPEM,
		PublicKeyPEM:  cfg.JWT.PublicKeyPEM,
		Issuer:        cfg.JWT.Issuer,
		Audience:      cfg.JWT.Audience,
	})
	if err != nil {
		return nil, err
	}

	hasher := password.NewBcryptHasher(password.DefaultCost)
	googleVerifier := google.NewGoogleVerifier(google.DefaultAllowedAudiences())

	// --- use case ---
	authService := application.NewAuthService(
		userRepo, oauthRepo, roleRepo, tokenService, hasher, googleVerifier)
	adminService := application.NewAdminService(userRepo, roleRepo)

	// --- input adapter ---
	authHandler := handler.NewAuthHandler(authService, tokenService)
	adminHandler := handler.NewAdminHandler(adminService)
	mw := handler.NewMiddleware(tokenService, authService)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// 🔴 ก่อนแก้: ทุก error ตอบ 500 หมด รวมถึง route ที่ไม่ตรงกับ
			// อะไรเลย (404) เพราะ Fiber ส่ง error เข้า ErrorHandler
			// นี้แม้แต่ตอน "ไม่เจอ route ที่ match" (ผ่าน fiber.ErrNotFound)
			// และโค้ดเดิมไม่ได้แยกว่า error เป็นชนิดไหน ยัดเป็น 500 ทั้งหมด
			//
			// ผลคือ metric/log ของ 4xx จริงกลายเป็น 5xx ปลอม ทำให้
			// error rate ที่วัดได้สูงเกินจริง และแยกไม่ออกว่า client
			// เรียกผิด (4xx) หรือ service พังจริง (5xx)
			//
			// เจอระหว่างตรวจสอบ VT-69 — ตอนนั้นยิง /login โดยไม่มี prefix
			// /api/v1/auth (ผิด endpoint) แล้วได้ 500 ทำให้เข้าใจผิดว่า
			// /login จริงพัง ทั้งที่ /api/v1/auth/login ทำงานปกติ (401
			// ตามที่ควรเป็นเมื่อ credential ผิด) — แก้ทั้งสองเรื่องพร้อมกัน
			code := fiber.StatusInternalServerError
			if fe, ok := err.(*fiber.Error); ok {
				code = fe.Code
			}
			return handler.SendError(c, code, err.Error())
		},
	})

	app.Use(requestid.New())
	// metrics มาก่อน access log เพื่อให้นับ request ที่ถูกปฏิเสธตั้งแต่ต้นทางด้วย
	app.Use(middleware.NewMetrics())
	app.Use(middleware.NewAccessLog())

	authHandler.RegisterRoutes(app.Group("/api/v1/auth"), mw)

	// --- Admin ---
	//
	// backoffice เรียก endpoint เหล่านี้อยู่ — จึงมีทางผ่านสำรองใน RequireRole
	// ให้บัญชีใน bootstrap_admins ผ่านได้แม้ token ใบเดิมยังไม่มี roles
	// ทำให้ปิดช่องโหว่ได้ทันทีโดยผู้ดูแลไม่ถูกล็อกออก
	adminHandler.RegisterRoutes(app.Group("/api/v1/auth/admin",
		mw.RequireAuth(), mw.RequireRole(domain.RoleSuperAdmin)))

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	// ให้ Prometheus มาดึง — เข้าถึงจากนอกคลัสเตอร์ไม่ได้
	// เพราะ ingress route เฉพาะ prefix /api/v1 เข้ามา
	app.Get("/metrics", middleware.MetricsHandler())

	return app, nil
}
