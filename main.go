package main

import (
	"context"
	"fmt"
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
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"google.golang.org/api/idtoken"
)

// --- Models ---
type User struct {
	ID           uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash *string   `json:"-"`
	FullName     string    `json:"fullName"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type OAuthIdentity struct {
	ID         uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index" json:"userId"`
	Provider   string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_provider_provider_id" json:"provider"`     // e.g., "apple", "google", "facebook"
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

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
		})

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
	
	// Migrate schema
	dbConn.AutoMigrate(&User{}, &OAuthIdentity{})
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

func initRSAKeys() {
	var err error
	privateKeyBytes, err = os.ReadFile("keys/private.pem")
	if err != nil {
		log.Fatal("Failed to read private key: ", err)
	}

	publicKeyBytes, err = os.ReadFile("keys/public.pem")
	if err != nil {
		log.Fatal("Failed to read public key: ", err)
	}

	parsedPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
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
func generateToken(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"name":  user.FullName,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	})
	return token.SignedString(parsedPrivateKey)
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
	}

	if err := dbConn.Create(&user).Error; err != nil {
		return sendError(c, 409, "Email already exists")
	}

	token, _ := generateToken(user)
	return c.Status(201).JSON(fiber.Map{
		"token": token,
		"user":  user,
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

	token, _ := generateToken(user)
	return c.JSON(fiber.Map{
		"token": token,
		"user":  user,
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
		authToken, _ := generateToken(user)
		return c.JSON(fiber.Map{"token": authToken, "user": user})
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
		
		authToken, _ := generateToken(user)
		return c.JSON(fiber.Map{"token": authToken, "user": user})
	}

	// New user!
	user = User{
		ID:       uuid.New(),
		Email:    email,
		FullName: req.FullName,
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

	authToken, _ := generateToken(user)
	return c.Status(201).JSON(fiber.Map{"token": authToken, "user": user})
}

func handleGetMe(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return sendError(c, 401, "Missing or invalid token")
	}
	tokenString := authHeader[7:]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	})

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
		"id":       user.ID,
		"email":    user.Email,
		"fullName": user.FullName,
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
	api.Get("/users", RequireAuth(), getAllUsers)
	api.Get("/me", RequireAuth(), handleGetMe)
	api.Get("/public-key", func(c *fiber.Ctx) error {
		return c.SendString(string(publicKeyBytes))
	})

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
			ID: u.ID,
			Email: u.Email,
			FullName: u.FullName,
		})
	}
	return c.JSON(safeUsers)
}
