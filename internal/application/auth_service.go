package application

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// SignupInput คือสิ่งที่ /signup ต้องการ
type SignupInput struct {
	Email    string
	Password string
	FullName string
}

// LoginInput คือสิ่งที่ /login ต้องการ
type LoginInput struct {
	Email    string
	Password string
}

// GoogleLoginInput คือสิ่งที่ /google ต้องการ
//
// ไม่มีฟิลด์ Email: request มีส่งมาจริงแต่โค้ดเดิมไม่เคยอ่าน
// อีเมลที่ใช้มาจาก id token ที่ Google เซ็นเท่านั้น ไม่ใช่จากค่าที่ client ส่งมา
type GoogleLoginInput struct {
	IDToken string

	// FullName จาก request ใช้เมื่อ Google ไม่ได้ส่ง claim "name" มา
	FullName string
}

// AuthResult คือสิ่งที่ /signup, /login, /google ตอบกลับ
type AuthResult struct {
	Token string
	User  domain.User
	Roles []string

	// Created = true เมื่อคำขอนี้สร้างบัญชีใหม่ — ผู้เรียกตอบ 201 ไม่ใช่ 200
	Created bool
}

// AuthService คือ use case ของการสมัคร เข้าสู่ระบบ และอ่านข้อมูลตัวเอง
type AuthService struct {
	users  port.UserRepository
	oauth  port.OAuthIdentityRepository
	roles  port.RoleRepository
	tokens port.TokenService
	hasher port.PasswordHasher
	google port.GoogleIdentityVerifier
}

func NewAuthService(
	users port.UserRepository,
	oauth port.OAuthIdentityRepository,
	roles port.RoleRepository,
	tokens port.TokenService,
	hasher port.PasswordHasher,
	google port.GoogleIdentityVerifier,
) *AuthService {
	return &AuthService{
		users:  users,
		oauth:  oauth,
		roles:  roles,
		tokens: tokens,
		hasher: hasher,
		google: google,
	}
}

// Signup สร้างบัญชีใหม่ด้วยอีเมลและรหัสผ่าน
func (s *AuthService) Signup(ctx context.Context, in SignupInput) (AuthResult, error) {
	if in.Email == "" || in.Password == "" {
		return AuthResult{}, ErrMissingCredentials
	}

	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return AuthResult{}, ErrHashPassword
	}

	user := domain.User{
		ID:           uuid.New(),
		Email:        in.Email,
		PasswordHash: &hash,
		FullName:     in.FullName,
		// 🔐 สมัครด้วยรหัสผ่าน = ยังไม่ยืนยันอีเมล
		//
		// ค่านี้เป็นตัวกันไม่ให้คนอื่นสมัครด้วยอีเมลที่อยู่ใน bootstrap_admins
		// แล้วชิง SUPER_ADMIN ไป — ห้ามเปลี่ยนเป็น true โดยไม่มีการยืนยันอีเมลจริง
		EmailVerified: false,
	}

	if err := s.users.Create(ctx, &user); err != nil {
		// repository คืน error ดิบมา การตีความอยู่ที่นี่: ที่ /signup
		// สาเหตุเดียวที่เกิดจริงคืออีเมลซ้ำ จึงตอบ 409
		// (GoogleLogin ตีความ error ตัวเดียวกันเป็น 500 — ดู ErrCreateUser)
		return AuthResult{}, ErrEmailExists
	}
	s.roles.EnsureDefaultRole(ctx, user.ID)

	token, roles, err := s.issueToken(ctx, user)
	if err != nil {
		return AuthResult{}, ErrIssueToken
	}
	return AuthResult{Token: token, User: user, Roles: roles, Created: true}, nil
}

// Login ตรวจรหัสผ่านแล้วออก token
//
// ไม่ตรวจว่าอีเมล/รหัสผ่านว่างไหม (ต่างจาก Signup) — ปล่อยให้หาบัญชีไม่เจอ
// แล้วตอบเหมือนรหัสผ่านผิด เป็นพฤติกรรมเดิม
func (s *AuthService) Login(ctx context.Context, in LoginInput) (AuthResult, error) {
	user, err := s.users.FindByEmail(ctx, in.Email)
	if err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}

	if user.PasswordHash == nil {
		return AuthResult{}, ErrPasswordLoginUnavailable
	}

	if err := s.hasher.Compare(*user.PasswordHash, in.Password); err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}

	s.roles.EnsureDefaultRole(ctx, user.ID)

	token, roles, err := s.issueToken(ctx, user)
	if err != nil {
		return AuthResult{}, ErrIssueToken
	}
	return AuthResult{Token: token, User: user, Roles: roles}, nil
}

// GoogleLogin เข้าสู่ระบบด้วย id token ของ Google
//
// มีสามเส้นทางตามลำดับเดิม:
//  1. เคยผูกบัญชีกับ Google ไว้แล้ว → เข้าสู่ระบบเลย
//  2. มีบัญชีด้วยอีเมลนี้อยู่แล้ว → ผูก Google เข้ากับบัญชีเดิม
//  3. ไม่มีเลย → สร้างบัญชีใหม่ (ตอบ 201)
func (s *AuthService) GoogleLogin(ctx context.Context, in GoogleLoginInput) (AuthResult, error) {
	identity, err := s.google.Verify(ctx, in.IDToken)
	if err != nil {
		// domain.ErrGoogleTokenInvalid / ErrGoogleAudienceInvalid /
		// ErrGoogleEmailMissing ส่งต่อให้ handler แปลงเป็นสถานะที่ต่างกัน
		return AuthResult{}, err
	}

	// ชื่อจาก Google ชนะชื่อที่ client ส่งมา เมื่อ Google ส่งมาจริง
	fullName := in.FullName
	if identity.FullName != "" {
		fullName = identity.FullName
	}

	// --- 1. เคยผูกบัญชีกับ Google ไว้แล้ว ---
	if linked, err := s.oauth.FindByProviderID(ctx, domain.ProviderGoogle, identity.Subject); err == nil {
		// 🔸 โค้ดเดิมทิ้ง error ของการอ่านผู้ใช้ตรงนี้
		//    (dbConn.First(&user, "id = ?", oauthIdentity.UserID) ไม่เช็ค err)
		//    ถ้าแถวใน o_auth_identities ชี้ไปผู้ใช้ที่ถูกลบไปแล้ว จะตอบ 200
		//    พร้อม user ที่เป็นค่าว่าง — foreign key ทำให้เกิดยาก
		//    คงพฤติกรรมเดิมไว้ ไม่เปลี่ยนในรอบนี้
		user, _ := s.users.FindByID(ctx, linked.UserID)

		s.markEmailVerified(ctx, &user)
		s.roles.EnsureDefaultRole(ctx, user.ID)

		token, roles, err := s.issueToken(ctx, user)
		if err != nil {
			return AuthResult{}, ErrIssueToken
		}
		return AuthResult{Token: token, User: user, Roles: roles}, nil
	}

	// --- 2. มีบัญชีด้วยอีเมลนี้อยู่แล้ว แต่ยังไม่ผูก Google ---
	if user, err := s.users.FindByEmail(ctx, identity.Email); err == nil {
		s.linkGoogleIdentity(ctx, user.ID, identity.Subject)

		if fullName != "" && user.FullName == "" {
			user.FullName = fullName
			// 🔸 โค้ดเดิมทิ้ง error ของ dbConn.Save(&user) ตรงนี้ — คงไว้เหมือนเดิม
			_ = s.users.Save(ctx, &user)
		}

		// Google ยืนยันอีเมลให้แล้ว และ Verify ตรวจลายเซ็นแล้ว
		// จุดนี้คือทางเดียวที่ email_verified จะกลายเป็น true
		s.markEmailVerified(ctx, &user)
		s.roles.EnsureDefaultRole(ctx, user.ID)

		token, roles, err := s.issueToken(ctx, user)
		if err != nil {
			return AuthResult{}, ErrIssueToken
		}
		return AuthResult{Token: token, User: user, Roles: roles}, nil
	}

	// --- 3. บัญชีใหม่ ---
	user := domain.User{
		ID:            uuid.New(),
		Email:         identity.Email,
		FullName:      fullName,
		EmailVerified: true, // มาจาก Google ที่ยืนยันอีเมลให้แล้ว
	}
	if err := s.users.Create(ctx, &user); err != nil {
		// error เดียวกับที่ Signup ตีความเป็น 409 แต่เส้นทางนี้ตอบ 500
		// เพราะอีเมลซ้ำตรงนี้หมายความว่าเพิ่งหาด้วยอีเมลแล้วไม่เจอ
		// แต่สร้างไม่ได้ ซึ่งไม่ใช่ความผิดของผู้เรียก
		return AuthResult{}, ErrCreateUser
	}

	s.linkGoogleIdentity(ctx, user.ID, identity.Subject)
	s.roles.EnsureDefaultRole(ctx, user.ID)

	token, roles, err := s.issueToken(ctx, user)
	if err != nil {
		return AuthResult{}, ErrIssueToken
	}
	return AuthResult{Token: token, User: user, Roles: roles, Created: true}, nil
}

// Me คืนข้อมูลผู้ใช้ที่ token ชี้ถึง พร้อม role ปัจจุบัน
//
// ⚠️ ตรวจ token ซ้ำอีกครั้งทั้งที่ RequireAuth ตรวจมาแล้ว
//
//	เป็นพฤติกรรมเดิมของ handleGetMe ที่ parse token ด้วยตัวเอง
//	ข้อความที่ตอบตอน token ใช้ไม่ได้จึงต่างจาก RequireAuth (ดู handler)
//	คงไว้เพราะเปลี่ยนมาอ่าน userId จาก context จะเปลี่ยนข้อความที่ตอบ
func (s *AuthService) Me(ctx context.Context, tokenString string) (domain.User, []string, error) {
	claims, err := s.tokens.Verify(tokenString)
	if err != nil {
		// 🔸 sub ที่ไม่ใช่สตริงเคยถูกกลืน (userIDStr, _ := claims["sub"].(string))
		//    แล้วเอาสตริงว่างไปหาผู้ใช้ ซึ่งหาไม่เจอ → ตอบ 404 ไม่ใช่ 401
		if errors.Is(err, domain.ErrTokenSubject) {
			return domain.User{}, nil, domain.ErrUserNotFound
		}
		return domain.User{}, nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		// sub ที่ไม่ใช่ UUID เคยถูกส่งเข้า query ตรงๆ แล้ว PostgreSQL ปฏิเสธ → 404
		return domain.User{}, nil, domain.ErrUserNotFound
	}

	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return domain.User{}, nil, err
	}
	return user, s.roles.RolesForUser(ctx, user.ID), nil
}

// Lookup หาบัญชีจากอีเมล ใช้กับ GET /lookup
func (s *AuthService) Lookup(ctx context.Context, email string) (domain.User, error) {
	return s.users.FindByEmail(ctx, email)
}

// ListUsers คืนผู้ใช้ทั้งหมด ใช้กับ GET /api/v1/auth/users
//
// คนละ endpoint กับหน้า admin — รูปแบบ response ต่างกันและไม่มี role ติดมาด้วย
func (s *AuthService) ListUsers(ctx context.Context) ([]domain.User, error) {
	users, err := s.users.FindAll(ctx)
	if err != nil {
		return nil, ErrListUsers
	}
	return users, nil
}

// issueToken รวมขั้นตอนที่ต้องทำทุกครั้งที่ออก token ไว้ที่เดียว
// เพื่อไม่ให้ลืม reconcile หรือลืมใส่ roles ในเส้นทางใดเส้นทางหนึ่ง
func (s *AuthService) issueToken(ctx context.Context, user domain.User) (string, []string, error) {
	s.reconcileBootstrapAdmin(ctx, user)
	roles := s.roles.RolesForUser(ctx, user.ID)
	token, err := s.tokens.Issue(user, roles)
	return token, roles, err
}

// reconcileBootstrapAdmin ให้ role กับบัญชีที่อยู่ในรายการ bootstrap_admins
//
// 🔐 กฎความปลอดภัยที่ห้ามละเมิด: grant ได้เฉพาะบัญชีที่ยืนยันอีเมลแล้วเท่านั้น
//
// เหตุผล: Signup สมัครด้วย password ได้โดยไม่ยืนยันอีเมล
// ถ้าไม่มีเงื่อนไขนี้ ใครก็ได้ที่รู้ว่าอีเมลไหนอยู่ในรายการ สามารถสมัครบัญชี
// ด้วยอีเมลนั้นก่อนเจ้าตัว แล้วได้ SUPER_ADMIN ไปทันที
//
// เรียกหลัง login/signup สำเร็จทุกครั้ง เพื่อให้บัญชีที่เพิ่งยืนยันอีเมล
// ได้สิทธิ์โดยไม่ต้องรัน migration ซ้ำ
func (s *AuthService) reconcileBootstrapAdmin(ctx context.Context, user domain.User) {
	if !user.EmailVerified {
		return
	}

	entry, err := s.roles.FindBootstrapAdmin(ctx, user.Email)
	if err != nil {
		return // ไม่ได้อยู่ในรายการ — กรณีปกติ
	}

	granted, err := s.roles.GrantRole(ctx, user.ID, entry.RoleCode)
	if err != nil {
		log.Printf("grant %s ให้ %s ไม่สำเร็จ: %v", entry.RoleCode, user.Email, err)
		return
	}
	if granted {
		log.Printf("🔐 grant %s ให้ %s (จาก bootstrap_admins)", entry.RoleCode, user.Email)
		// ใช้ entry.Email ไม่ใช่ user.Email — ต้องตรงตัวพิมพ์กับแถวในตาราง
		if err := s.roles.MarkBootstrapAdminGranted(ctx, entry.Email); err != nil {
			log.Printf("บันทึกเวลา grant ให้ %s ไม่สำเร็จ: %v", entry.Email, err)
		}
	}
}

// markEmailVerified ตั้ง email_verified = true เมื่อยืนยันผ่าน provider ที่เชื่อถือได้
//
// เขียนลงฐานข้อมูลเฉพาะตอนที่ค่ายังไม่เป็น true เพื่อไม่ให้ยิง UPDATE ทุกครั้งที่ login
func (s *AuthService) markEmailVerified(ctx context.Context, user *domain.User) {
	if user.EmailVerified {
		return
	}
	if err := s.users.MarkEmailVerified(ctx, user.ID); err != nil {
		log.Printf("ตั้ง email_verified ให้ %s ไม่สำเร็จ: %v", user.Email, err)
		return
	}
	user.EmailVerified = true
}

// linkGoogleIdentity ผูก Google เข้ากับบัญชีหนึ่ง
//
// 🔸 โค้ดเดิมทิ้ง error ของ dbConn.Create(&newIdentity) ทั้งสองจุดที่เรียก
//
//	คงไว้เหมือนเดิม — ถ้าผูกไม่สำเร็จ ผู้ใช้ยังเข้าสู่ระบบได้ในรอบนี้
//	แล้วรอบหน้าจะเข้าทางเส้นทางที่ 2 (หาด้วยอีเมล) อีกครั้ง
func (s *AuthService) linkGoogleIdentity(ctx context.Context, userID uuid.UUID, googleSub string) {
	identity := domain.OAuthIdentity{
		ID:         uuid.New(),
		UserID:     userID,
		Provider:   domain.ProviderGoogle,
		ProviderID: googleSub,
	}
	_ = s.oauth.Create(ctx, &identity)
}
