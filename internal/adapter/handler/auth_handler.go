package handler

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"vertex-auth-service/internal/application"
	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// --- DTO ของ request (รูปร่างเป็นสัญญากับ client อยู่แล้ว ห้ามเปลี่ยนชื่อฟิลด์) ---

type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"fullName"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// GoogleLoginRequest — ฟิลด์ Email ยังอยู่เพราะ client ส่งมาจริง
// แต่ไม่เคยถูกใช้: อีเมลที่เชื่อถือได้มาจาก id token ที่ Google เซ็นเท่านั้น
type GoogleLoginRequest struct {
	IdToken  string `json:"idToken"`
	Email    string `json:"email"`
	FullName string `json:"fullName"`
}

// AuthHandler รับ request ของการสมัคร เข้าสู่ระบบ และอ่านข้อมูลตัวเอง
type AuthHandler struct {
	auth *application.AuthService

	// keys ตอบ /public-key กับ /key-info ซึ่งเป็นเรื่องของการดูแลระบบ
	// ไม่ใช่ use case ของผู้ใช้ จึงต่อกับ port ตรงๆ ไม่ผ่าน AuthService
	keys port.KeyInspector
}

func NewAuthHandler(auth *application.AuthService, keys port.KeyInspector) *AuthHandler {
	return &AuthHandler{auth: auth, keys: keys}
}

func (h *AuthHandler) Signup(c *fiber.Ctx) error {
	var req SignupRequest
	if err := c.BodyParser(&req); err != nil {
		return SendError(c, 400, "Invalid request body")
	}

	result, err := h.auth.Signup(c.UserContext(), application.SignupInput{
		Email:    req.Email,
		Password: req.Password,
		FullName: req.FullName,
	})
	if err != nil {
		switch {
		case errors.Is(err, application.ErrMissingCredentials):
			return SendError(c, 400, "Email and Password are required")
		case errors.Is(err, application.ErrHashPassword):
			return SendError(c, 500, "Error hashing password")
		case errors.Is(err, application.ErrEmailExists):
			return SendError(c, 409, "Email already exists")
		default:
			return SendError(c, 500, issueTokenMessage)
		}
	}

	return c.Status(201).JSON(fiber.Map{
		"token": result.Token,
		"user":  result.User,
		"roles": result.Roles,
	})
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return SendError(c, 400, "Invalid request body")
	}

	result, err := h.auth.Login(c.UserContext(), application.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		switch {
		case errors.Is(err, application.ErrInvalidCredentials):
			return SendError(c, 401, "Invalid email or password")
		case errors.Is(err, application.ErrPasswordLoginUnavailable):
			return SendError(c, 401, "Please sign in with Apple")
		default:
			return SendError(c, 500, issueTokenMessage)
		}
	}

	return c.JSON(fiber.Map{
		"token": result.Token,
		"user":  result.User,
		"roles": result.Roles,
	})
}

func (h *AuthHandler) GoogleLogin(c *fiber.Ctx) error {
	var req GoogleLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return SendError(c, 400, "Invalid request payload")
	}

	result, err := h.auth.GoogleLogin(c.UserContext(), application.GoogleLoginInput{
		IDToken:  req.IdToken,
		FullName: req.FullName,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrGoogleTokenInvalid):
			return SendError(c, 401, "Invalid Google ID Token")
		case errors.Is(err, domain.ErrGoogleAudienceInvalid):
			return SendError(c, 401, "Invalid Google Client ID audience")
		case errors.Is(err, domain.ErrGoogleEmailMissing):
			return SendError(c, 400, "Google account has no email")
		case errors.Is(err, application.ErrCreateUser):
			return SendError(c, 500, "Failed to create user account")
		default:
			return SendError(c, 500, issueTokenMessage)
		}
	}

	body := fiber.Map{"token": result.Token, "user": result.User, "roles": result.Roles}
	if result.Created {
		return c.Status(201).JSON(body)
	}
	return c.JSON(body)
}

// Me คืนข้อมูลผู้ใช้จาก token
//
// ⚠️ อ่าน token จาก header เองอีกครั้งทั้งที่ RequireAuth ตรวจมาแล้ว
//
//	เป็นพฤติกรรมเดิมของ handleGetMe — ข้อความที่ตอบตอน token ใช้ไม่ได้
//	ต่างจาก RequireAuth ("Invalid token" ไม่ใช่ "Invalid or expired token")
//	เส้นทางนี้เข้าถึงได้ยากเพราะ RequireAuth กรองไปก่อนแล้ว
//	แต่คงไว้เพื่อไม่ให้ข้อความที่ตอบเปลี่ยน
func (h *AuthHandler) Me(c *fiber.Ctx) error {
	tokenString, ok := bearerToken(c)
	if !ok {
		return SendError(c, 401, "Missing or invalid token")
	}

	user, roles, err := h.auth.Me(c.UserContext(), tokenString)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrTokenClaims):
			return SendError(c, 401, "Invalid token claims")
		case errors.Is(err, domain.ErrUserNotFound):
			return SendError(c, 404, "User not found")
		default:
			return SendError(c, 401, "Invalid token")
		}
	}

	return c.JSON(fiber.Map{
		"id":            user.ID,
		"email":         user.Email,
		"fullName":      user.FullName,
		"emailVerified": user.EmailVerified,
		"roles":         roles,
	})
}

func (h *AuthHandler) Lookup(c *fiber.Ctx) error {
	user, err := h.auth.Lookup(c.UserContext(), c.Query("email"))
	if err != nil {
		return SendError(c, 404, "User not found")
	}
	return c.JSON(fiber.Map{"id": user.ID, "email": user.Email, "fullName": user.FullName})
}

// safeUser คือรูปแบบ response ของ GET /users — ไม่มี hash รหัสผ่าน
type safeUser struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"fullName"`
}

// ListUsers ตอบ GET /api/v1/auth/users
//
// คนละ endpoint กับ /admin/users — endpoint นี้ไม่ส่ง role และไม่ส่ง
// emailVerified กลับไป
func (h *AuthHandler) ListUsers(c *fiber.Ctx) error {
	users, err := h.auth.ListUsers(c.UserContext())
	if err != nil {
		return SendError(c, 500, "Failed to retrieve users")
	}

	out := make([]safeUser, 0, len(users))
	for _, u := range users {
		out = append(out, safeUser{ID: u.ID, Email: u.Email, FullName: u.FullName})
	}
	return c.JSON(out)
}

// PublicKey คืน public key ทุกใบที่ยอมรับ (รูปแบบเดิม: PEM ต่อกัน)
// service ปลายทางเอาไปใส่ JWT_PUBLIC_KEYS ได้ตรงๆ
func (h *AuthHandler) PublicKey(c *fiber.Ctx) error {
	return c.SendString(string(h.keys.PublicKeyPEM()))
}

// KeyInfo ใช้ตรวจตอน rotate ว่าแต่ละ pod เซ็นด้วยคีย์ใบไหนอยู่
func (h *AuthHandler) KeyInfo(c *fiber.Ctx) error {
	info := h.keys.KeyInfo()
	return c.JSON(fiber.Map{
		"signingKeyId":   info.SigningKeyID,
		"acceptedKeyIds": info.AcceptedKeyIDs,
		"tokenTtl":       info.TokenTTL,
	})
}

// issueTokenMessage ตอบตอนเซ็น token ไม่สำเร็จ
//
// 🔸 เส้นทางนี้ไม่เคยมีมาก่อน: main.go เดิมทิ้ง error ของ issueToken
//
//	(token, roles, _ := issueToken(user)) แล้วตอบ 200/201 พร้อม token ว่าง
//	ตอนนี้ตอบ 500 แทน — เส้นทางสำเร็จไม่เปลี่ยนแปลงเลย
const issueTokenMessage = "Failed to issue token"

// RegisterRoutes ผูก route ของ /api/v1/auth เข้ากับ handler
//
// route ที่ต้องยืนยันตัวตนรับ middleware เข้ามาเป็นพารามิเตอร์
// เพื่อให้เห็นการป้องกันของทุก route ในที่เดียว
func (h *AuthHandler) RegisterRoutes(api fiber.Router, mw *Middleware) {
	api.Post("/signup", h.Signup)
	api.Post("/login", h.Login)
	api.Post("/google", h.GoogleLogin)
	api.Get("/lookup", mw.RequireAuth(), h.Lookup)
	// ⚠️ /users อยู่หลัง RequireRole(SUPER_ADMIN)
	//    เดิมเปิดให้ผู้ใช้ที่ login แล้วทุกคนดึงอีเมลของทุกคนในระบบได้
	api.Get("/users", mw.RequireAuth(), mw.RequireRole(domain.RoleSuperAdmin), h.ListUsers)
	api.Get("/me", mw.RequireAuth(), h.Me)
	api.Get("/public-key", h.PublicKey)
	api.Get("/key-info", h.KeyInfo)
}
