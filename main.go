package main

import (
	"context"
	"crypto/rsa"
	"log"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/idtoken"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Models ---
type User struct {
	ID           uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash *string   `json:"-"`
	FullName     string    `json:"fullName"`
	// EmailVerified จำเป็นต่อความปลอดภัยของ bootstrap admin
	// signup ด้วย password ตั้งเป็น false เสมอ — login ผ่าน Google ถึงจะเป็น true
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type OAuthIdentity struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index" json:"userId"`
	Provider   string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_provider_provider_id" json:"provider"`    // e.g., "apple", "google", "facebook"
	ProviderID string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_provider_provider_id" json:"providerId"` // The sub from the provider
	CreatedAt  time.Time `json:"createdAt"`
}

// --- Globals ---
var DB *gorm.Config
var dbConn *gorm.DB
var jwks *keyfunc.JWKS
var rsaPrivateKey *jwt.Token
var privateKeyBytes []byte
var publicKeyBytes []byte
var parsedPrivateKey interface{}

// signingKeyID คือ kid ของคีย์ที่ใช้เซ็นอยู่ตอนนี้ ใส่ลงใน token header
// ทำให้ผู้ตรวจเลือกคีย์ได้ถูกใบระหว่างช่วง rotate
var signingKeyID string

// acceptedPublicKeys คือ public key ทุกใบที่ auth-service ยอมรับตอน verify
// (ใช้ที่ RequireAuth และ /me) — ระหว่าง rotate จะมีสองใบ
var acceptedPublicKeys []*rsa.PublicKey

// --- DTOs ---
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"fullName"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type GoogleLoginRequest struct {
	IdToken  string `json:"idToken"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}

// RequireAuth middleware verifies the JWT token
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			return sendError(c, 401, "Missing or invalid token")
		}
		tokenString := authHeader[7:]

		token, err := jwt.Parse(tokenString, verificationKeyfunc)

		if err != nil || !token.Valid {
			return sendError(c, 401, "Invalid or expired token")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return sendError(c, 401, "Invalid token claims")
		}

		userIDStr, ok := claims["sub"].(string)
		if !ok {
			return sendError(c, 401, "Invalid token subject")
		}

		c.Locals("userId", userIDStr)
		c.Locals("roles", rolesFromClaims(claims))
		return c.Next()
	}
}

// --- Initialization ---
func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// Assuming local k8s DNS or docker-compose
		dsn = "host=vertex-postgres-postgresql.default.svc.cluster.local user=postgres password=password dbname=auth port=5432 sslmode=disable"
	}
	var err error
	dbConn, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("WARNING: Failed to connect to DB, retrying with localhost...")
		dsn = "host=localhost user=postgres password=password dbname=auth port=5432 sslmode=disable"
		dbConn, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Fatal("Failed to connect to database: ", err)
		}
	}

	// AutoMigrate ถูกถอดออกแล้ว — schema ทั้งหมดจัดการด้วย Flyway
	// (repo vertex-migrations, schema auth)
	//
	// เหตุผลที่เลิกใช้:
	//   - รันทุก pod ที่ start → replica ที่ 2, 3 ต้องรอ lock ก่อนถึงจะขึ้น
	//   - ลบ/rename column ไม่ได้ ทำ data migration ไม่ได้ seed ข้อมูลไม่ได้
	//   - review ใน PR ไม่ได้ และ schema จริงค่อยๆ ห่างจากสิ่งที่ควบคุมได้
	//
	// หน้าที่ของแอปเหลือแค่ "ยืนยันว่า migration รันแล้วจริง" แล้วล้มทันทีถ้ายัง
	assertSchemaReady()
}

func initAppleJWKS() {
	var err error
	jwks, err = keyfunc.Get("https://appleid.apple.com/auth/keys", keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	})
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}
}

// initRSAKeys อ่านคีย์จาก env ก่อน แล้วค่อย fallback ไปอ่านไฟล์ใน image
//
// การอ่านจาก env ทำให้ rotate key ได้ด้วยการแก้ Secret อย่างเดียว
// ไม่ต้อง rebuild และ redeploy ทุก service
func initRSAKeys() {
	var err error

	if jwtPrivateKeyPEM != "" {
		privateKeyBytes = []byte(jwtPrivateKeyPEM)
		log.Println("อ่าน private key จาก JWT_PRIVATE_KEY")
	} else {
		privateKeyBytes, err = os.ReadFile("keys/private.pem")
		if err != nil {
			log.Fatal("อ่าน private key ไม่ได้: ", err)
		}
		log.Println("⚠️  อ่าน private key จากไฟล์ใน image — ควรย้ายไปใช้ JWT_PRIVATE_KEY จาก Secret")
		log.Println("    keys/private.pem เคยถูก commit เข้า git จึงต้องถือว่ารั่วแล้วและต้อง rotate")
	}

	// JWT_PUBLIC_KEYS รับหลายใบ ใช้ระหว่าง rotate เพื่อให้ยังตรวจ token
	// ที่เซ็นด้วยคีย์เก่าและยังไม่หมดอายุได้
	switch {
	case jwtPublicKeysPEM != "":
		publicKeyBytes = []byte(jwtPublicKeysPEM)
	case jwtPublicKeyPEM != "":
		publicKeyBytes = []byte(jwtPublicKeyPEM)
	default:
		publicKeyBytes, err = os.ReadFile("keys/public.pem")
		if err != nil {
			log.Fatal("อ่าน public key ไม่ได้: ", err)
		}
	}

	priv, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		log.Fatal("parse private key ไม่สำเร็จ: ", err)
	}
	parsedPrivateKey = priv

	acceptedPublicKeys, err = parsePublicKeys(string(publicKeyBytes))
	if err != nil {
		log.Fatal("parse public key ไม่สำเร็จ: ", err)
	}

	signingKeyID = keyID(&priv.PublicKey)
	log.Printf("เซ็น token ด้วยคีย์ kid=%s", signingKeyID)

	// คีย์ที่ใช้เซ็นต้องอยู่ในชุดที่ยอมรับด้วย ไม่งั้น token ที่ตัวเองออกจะ verify ไม่ผ่าน
	found := false
	for _, k := range acceptedPublicKeys {
		if keyID(k) == signingKeyID {
			found = true
		}
		log.Printf("ยอมรับ public key kid=%s", keyID(k))
	}
	if !found {
		log.Fatal("public key ที่ตั้งค่าไว้ไม่มีใบที่คู่กับ private key ที่ใช้เซ็น — ตรวจ JWT_PUBLIC_KEYS")
	}
	if len(acceptedPublicKeys) > 1 {
		log.Printf("⚠️  ตั้งค่า public key ไว้ %d ใบ — โหมด rotate เท่านั้น "+
			"เอาใบเก่าออกเมื่อผ่านไปนานกว่าอายุ token ที่ยาวที่สุด (%s)",
			len(acceptedPublicKeys), accessTokenTTL)
	}
}

func sendError(c *fiber.Ctx, status int, message string) error {
	reqID := c.Get("X-Request-Id")
	if reqID == "" {
		if val := c.Locals("requestid"); val != nil {
			reqID = val.(string)
		}
	}
	return c.Status(status).JSON(fiber.Map{
		"error":     message,
		"requestId": reqID,
	})
}

// --- JWT Utils ---

// accessTokenTTL — 72 ชั่วโมงเป็นค่าเดิม
//
// 🔸 ยาวเกินไปสำหรับ access token: token ที่หลุดใช้ได้ 3 วันเต็มและเพิกถอนไม่ได้
//
//	ควรลดเหลือ 15–60 นาที + เพิ่ม refresh token — เป็นงานแยกที่ต้องแก้ client ด้วย
//	ตอนนี้คงไว้เพื่อไม่ให้ผู้ใช้เดิมถูกบังคับ login ใหม่
var accessTokenTTL = 72 * time.Hour

// generateToken ออก access token
//
// เพิ่ม roles / iss / aud / iat / jti จากเดิมที่มีแค่ sub, email, name, exp
//
// ⚠️ pet-service ยังไม่บังคับตรวจ iss/aud (ต้องรอให้ token เดิมหมดอายุก่อน
//
//	ไม่งั้น token ที่ผู้ใช้ถืออยู่จะใช้ไม่ได้ทันทีทั้งระบบ)
//	การใส่มาก่อนคือขั้นแรกของการปล่อยแบบ 2 เฟส
func generateToken(user User, roles []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"name":  user.FullName,
		"roles": roles,
		"iat":   now.Unix(),
		"jti":   uuid.New().String(),
		"exp":   now.Add(accessTokenTTL).Unix(),
	}
	if jwtIssuer != "" {
		claims["iss"] = jwtIssuer
	}
	if jwtAudience != "" {
		claims["aud"] = jwtAudience
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid ทำให้ผู้ตรวจเลือกคีย์ได้ถูกใบทันทีระหว่างช่วง rotate
	if signingKeyID != "" {
		token.Header["kid"] = signingKeyID
	}
	return token.SignedString(parsedPrivateKey)
}

// issueToken รวมขั้นตอนที่ต้องทำทุกครั้งที่ออก token ไว้ที่เดียว
// เพื่อไม่ให้ลืม reconcile หรือลืมใส่ roles ในเส้นทางใดเส้นทางหนึ่ง
func issueToken(user User) (string, []string, error) {
	reconcileBootstrapAdmin(dbConn, user)
	roles := rolesForUser(dbConn, user.ID)
	token, err := generateToken(user, roles)
	return token, roles, err
}

// --- Handlers ---
func handleSignup(c *fiber.Ctx) error {
	var req SignupRequest
	if err := c.BodyParser(&req); err != nil {
		return sendError(c, 400, "Invalid request body")
	}

	if req.Email == "" || req.Password == "" {
		return sendError(c, 400, "Email and Password are required")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return sendError(c, 500, "Error hashing password")
	}
	hashStr := string(hash)

	user := User{
		ID:           uuid.New(),
		Email:        req.Email,
		PasswordHash: &hashStr,
		FullName:     req.FullName,
		// 🔐 สมัครด้วยรหัสผ่าน = ยังไม่ยืนยันอีเมล
		//
		// ค่านี้เป็นตัวกันไม่ให้คนอื่นสมัครด้วยอีเมลที่อยู่ใน bootstrap_admins
		// แล้วชิง SUPER_ADMIN ไป — ห้ามเปลี่ยนเป็น true โดยไม่มีการยืนยันอีเมลจริง
		EmailVerified: false,
	}

	if err := dbConn.Create(&user).Error; err != nil {
		return sendError(c, 409, "Email already exists")
	}
	ensureDefaultRole(dbConn, user.ID)

	token, roles, _ := issueToken(user)
	return c.Status(201).JSON(fiber.Map{
		"token": token,
		"user":  user,
		"roles": roles,
	})
}

func handleLogin(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return sendError(c, 400, "Invalid request body")
	}

	var user User
	if err := dbConn.Where("email = ?", req.Email).First(&user).Error; err != nil {
		return sendError(c, 401, "Invalid email or password")
	}

	if user.PasswordHash == nil {
		return sendError(c, 401, "Please sign in with Apple")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		return sendError(c, 401, "Invalid email or password")
	}

	ensureDefaultRole(dbConn, user.ID)
	token, roles, _ := issueToken(user)
	return c.JSON(fiber.Map{
		"token": token,
		"user":  user,
		"roles": roles,
	})
}

func handleGoogleLogin(c *fiber.Ctx) error {
	var req GoogleLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return sendError(c, 400, "Invalid request payload")
	}

	payload, err := idtoken.Validate(context.Background(), req.IdToken, "")
	if err != nil {
		return sendError(c, 401, "Invalid Google ID Token")
	}

	validClients := map[string]bool{
		"565361629384-nm0k3gs5affdnva1gjlfb2b9musj0614.apps.googleusercontent.com": true, // iOS
		"565361629384-lre3e35dhoj151akegf1bskv38st9oe3.apps.googleusercontent.com": true, // Web
	}

	if !validClients[payload.Audience] {
		return sendError(c, 401, "Invalid Google Client ID audience")
	}

	googleSub := payload.Subject
	email, ok := payload.Claims["email"].(string)
	if !ok || email == "" {
		return sendError(c, 400, "Google account has no email")
	}

	// Override full name from Google if available, else use request
	if name, ok := payload.Claims["name"].(string); ok && name != "" {
		req.FullName = name
	}

	var oauthIdentity OAuthIdentity
	err = dbConn.Where("provider = ? AND provider_id = ?", "google", googleSub).First(&oauthIdentity).Error
	if err == nil {
		// Found existing oauth identity, get user and login
		var user User
		dbConn.First(&user, "id = ?", oauthIdentity.UserID)
		markEmailVerified(&user)
		ensureDefaultRole(dbConn, user.ID)
		authToken, roles, _ := issueToken(user)
		return c.JSON(fiber.Map{"token": authToken, "user": user, "roles": roles})
	}

	var user User
	err = dbConn.Where("email = ?", email).First(&user).Error
	if err == nil {
		// Found by email, link google provider
		newIdentity := OAuthIdentity{
			ID:         uuid.New(),
			UserID:     user.ID,
			Provider:   "google",
			ProviderID: googleSub,
		}
		dbConn.Create(&newIdentity)

		if req.FullName != "" && user.FullName == "" {
			user.FullName = req.FullName
			dbConn.Save(&user)
		}

		// Google ยืนยันอีเมลให้แล้ว และ idtoken.Validate ตรวจลายเซ็นแล้ว
		// จุดนี้คือทางเดียวที่ email_verified จะกลายเป็น true
		markEmailVerified(&user)
		ensureDefaultRole(dbConn, user.ID)
		authToken, roles, _ := issueToken(user)
		return c.JSON(fiber.Map{"token": authToken, "user": user, "roles": roles})
	}

	// New user!
	user = User{
		ID:            uuid.New(),
		Email:         email,
		FullName:      req.FullName,
		EmailVerified: true, // มาจาก Google ที่ยืนยันอีเมลให้แล้ว
	}

	if err := dbConn.Create(&user).Error; err != nil {
		return sendError(c, 500, "Failed to create user account")
	}

	newIdentity := OAuthIdentity{
		ID:         uuid.New(),
		UserID:     user.ID,
		Provider:   "google",
		ProviderID: googleSub,
	}
	dbConn.Create(&newIdentity)

	ensureDefaultRole(dbConn, user.ID)
	authToken, roles, _ := issueToken(user)
	return c.Status(201).JSON(fiber.Map{"token": authToken, "user": user, "roles": roles})
}

func handleGetMe(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return sendError(c, 401, "Missing or invalid token")
	}
	tokenString := authHeader[7:]

	token, err := jwt.Parse(tokenString, verificationKeyfunc)
	if err != nil || !token.Valid {
		return sendError(c, 401, "Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return sendError(c, 401, "Invalid token claims")
	}

	userIDStr, _ := claims["sub"].(string)
	var user User
	if err := dbConn.First(&user, "id = ?", userIDStr).Error; err != nil {
		return sendError(c, 404, "User not found")
	}

	return c.JSON(fiber.Map{
		"id":            user.ID,
		"email":         user.Email,
		"fullName":      user.FullName,
		"emailVerified": user.EmailVerified,
		"roles":         rolesForUser(dbConn, user.ID),
	})
}

func main() {
	initDB()
	initAppleJWKS()
	initRSAKeys()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return sendError(c, 500, err.Error())
		},
	})

	app.Use(requestid.New())
	app.Use(logger.New(logger.Config{
		Format: `{"time":"${time}","requestId":"${locals:requestid}","status":${status},"method":"${method}","path":"${path}","latency":"${latency}"}` + "\n",
	}))

	api := app.Group("/api/v1/auth")
	api.Post("/signup", handleSignup)
	api.Post("/login", handleLogin)
	api.Post("/google", handleGoogleLogin)
	api.Get("/lookup", RequireAuth(), lookupUser)
	api.Get("/users", RequireAuth(), requireRole(RoleSuperAdmin), getAllUsers)
	api.Get("/me", RequireAuth(), handleGetMe)
	// คืน public key ทุกใบที่ยอมรับ (รูปแบบเดิม: PEM ต่อกัน)
	// service ปลายทางเอาไปใส่ JWT_PUBLIC_KEYS ได้ตรงๆ
	api.Get("/public-key", func(c *fiber.Ctx) error {
		return c.SendString(string(publicKeyBytes))
	})

	// endpoint สำหรับตรวจตอน rotate ว่าแต่ละ pod เซ็นด้วยคีย์ใบไหนอยู่
	api.Get("/key-info", func(c *fiber.Ctx) error {
		accepted := make([]string, 0, len(acceptedPublicKeys))
		for _, k := range acceptedPublicKeys {
			accepted = append(accepted, keyID(k))
		}
		return c.JSON(fiber.Map{
			"signingKeyId":   signingKeyID,
			"acceptedKeyIds": accepted,
			"tokenTtl":       accessTokenTTL.String(),
		})
	})

	// --- Admin ---
	//
	// ⚠️ /users ย้ายมาอยู่หลัง requireRole(SUPER_ADMIN)
	//    เดิมเปิดให้ผู้ใช้ที่ login แล้วทุกคนดึงอีเมลของทุกคนในระบบได้
	//
	//    backoffice เรียก endpoint นี้อยู่ — จึงมีทางผ่านสำรองใน requireRole
	//    ให้บัญชีใน bootstrap_admins ผ่านได้แม้ token ใบเดิมยังไม่มี roles
	//    ทำให้ปิดช่องโหว่ได้ทันทีโดยผู้ดูแลไม่ถูกล็อกออก
	admin := app.Group("/api/v1/auth/admin", RequireAuth(), requireRole(RoleSuperAdmin))
	admin.Get("/users", handleAdminListUsers)
	admin.Put("/users/:id/roles", handleAdminUpdateRoles)
	admin.Get("/roles", handleListRoles)

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	log.Fatal(app.Listen(":4000"))
}

func lookupUser(c *fiber.Ctx) error {
	email := c.Query("email")
	var user User
	if err := dbConn.Where("email = ?", email).First(&user).Error; err != nil {
		return sendError(c, 404, "User not found")
	}
	return c.JSON(fiber.Map{"id": user.ID, "email": user.Email, "fullName": user.FullName})
}

func getAllUsers(c *fiber.Ctx) error {
	var users []User
	if err := dbConn.Find(&users).Error; err != nil {
		return sendError(c, 500, "Failed to retrieve users")
	}

	// Create a safe representation without password hashes
	type SafeUser struct {
		ID       uuid.UUID `json:"id"`
		Email    string    `json:"email"`
		FullName string    `json:"fullName"`
	}

	safeUsers := make([]SafeUser, 0, len(users))
	for _, u := range users {
		safeUsers = append(safeUsers, SafeUser{
			ID:       u.ID,
			Email:    u.Email,
			FullName: u.FullName,
		})
	}
	return c.JSON(safeUsers)
}
