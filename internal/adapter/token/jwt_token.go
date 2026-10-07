// Package token ออกและตรวจ access token ด้วย RSA
//
// ไลบรารี JWT กับรายละเอียดของคีย์ไม่รั่วออกจากแพ็กเกจนี้ —
// ชั้น application เห็นแค่ port.TokenService
package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// DefaultAccessTokenTTL — 72 ชั่วโมงเป็นค่าเดิม
//
// 🔸 ยาวเกินไปสำหรับ access token: token ที่หลุดใช้ได้ 3 วันเต็มและเพิกถอนไม่ได้
//
//	ควรลดเหลือ 15–60 นาที + เพิ่ม refresh token — เป็นงานแยกที่ต้องแก้ client ด้วย
//	ตอนนี้คงไว้เพื่อไม่ให้ผู้ใช้เดิมถูกบังคับ login ใหม่
const DefaultAccessTokenTTL = 72 * time.Hour

// ไฟล์คีย์ใน image ใช้เมื่อไม่ได้ตั้งค่าผ่าน env
const (
	privateKeyFile = "keys/private.pem"
	publicKeyFile  = "keys/public.pem"
)

// Config คือค่าที่ JWTTokenService ต้องใช้ตอนสร้าง
type Config struct {
	// PrivateKeyPEM มาก่อนไฟล์ใน image เสมอ — ทำให้ rotate key ผ่าน Secret ได้
	// โดยไม่ต้อง rebuild และ redeploy ทุก service
	PrivateKeyPEM string

	// PublicKeysPEM รับ PEM หลายบล็อกต่อกัน ใช้ระหว่าง rotate เพื่อให้ยังตรวจ
	// token ที่เซ็นด้วยคีย์เก่าและยังไม่หมดอายุได้ — มาก่อน PublicKeyPEM
	PublicKeysPEM string
	PublicKeyPEM  string

	// Issuer / Audience ใส่ลง token เมื่อไม่ว่าง
	Issuer   string
	Audience string

	// TTL ว่างไว้ได้ จะใช้ DefaultAccessTokenTTL
	TTL time.Duration
}

// JWTTokenService implements port.TokenService และ port.KeyInspector
//
// คีย์ที่โหลดแล้วเป็นฟิลด์ของ struct ไม่ใช่ตัวแปร global อย่างเดิม
type JWTTokenService struct {
	privateKey   *rsa.PrivateKey
	acceptedKeys []*rsa.PublicKey

	// signingKeyID คือ kid ของคีย์ที่ใช้เซ็นอยู่ตอนนี้ ใส่ลงใน token header
	// ทำให้ผู้ตรวจเลือกคีย์ได้ถูกใบระหว่างช่วง rotate
	signingKeyID string

	// publicKeyBytes คือ PEM ดิบตามที่ตั้งค่ามา ใช้ตอบ /public-key
	publicKeyBytes []byte

	issuer   string
	audience string
	ttl      time.Duration
}

// NewJWTTokenService อ่านคีย์จาก config ก่อน แล้วค่อย fallback ไปอ่านไฟล์ใน image
//
// คืน error แทนการ log.Fatal เอง — การตัดสินว่าจะล้มทั้ง process ไหม
// เป็นหน้าที่ของ composition root (cmd/server) ไม่ใช่ของ adapter
func NewJWTTokenService(cfg Config) (*JWTTokenService, error) {
	privateKeyBytes, err := loadPrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err := loadPublicKeys(cfg)
	if err != nil {
		return nil, err
	}

	priv, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key ไม่สำเร็จ: %w", err)
	}

	accepted, err := parsePublicKeys(string(publicKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("parse public key ไม่สำเร็จ: %w", err)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = DefaultAccessTokenTTL
	}

	s := &JWTTokenService{
		privateKey:     priv,
		acceptedKeys:   accepted,
		signingKeyID:   keyID(&priv.PublicKey),
		publicKeyBytes: publicKeyBytes,
		issuer:         cfg.Issuer,
		audience:       cfg.Audience,
		ttl:            ttl,
	}

	log.Printf("เซ็น token ด้วยคีย์ kid=%s", s.signingKeyID)

	// คีย์ที่ใช้เซ็นต้องอยู่ในชุดที่ยอมรับด้วย ไม่งั้น token ที่ตัวเองออกจะ verify ไม่ผ่าน
	found := false
	for _, k := range accepted {
		if keyID(k) == s.signingKeyID {
			found = true
		}
		log.Printf("ยอมรับ public key kid=%s", keyID(k))
	}
	if !found {
		return nil, fmt.Errorf(
			"public key ที่ตั้งค่าไว้ไม่มีใบที่คู่กับ private key ที่ใช้เซ็น — ตรวจ JWT_PUBLIC_KEYS")
	}
	if len(accepted) > 1 {
		log.Printf("⚠️  ตั้งค่า public key ไว้ %d ใบ — โหมด rotate เท่านั้น "+
			"เอาใบเก่าออกเมื่อผ่านไปนานกว่าอายุ token ที่ยาวที่สุด (%s)",
			len(accepted), ttl)
	}

	return s, nil
}

func loadPrivateKey(cfg Config) ([]byte, error) {
	if cfg.PrivateKeyPEM != "" {
		log.Println("อ่าน private key จาก JWT_PRIVATE_KEY")
		return []byte(cfg.PrivateKeyPEM), nil
	}

	b, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("อ่าน private key ไม่ได้: %w", err)
	}
	log.Println("⚠️  อ่าน private key จากไฟล์ใน image — ควรย้ายไปใช้ JWT_PRIVATE_KEY จาก Secret")
	log.Println("    keys/private.pem เคยถูก commit เข้า git จึงต้องถือว่ารั่วแล้วและต้อง rotate")
	return b, nil
}

func loadPublicKeys(cfg Config) ([]byte, error) {
	switch {
	case cfg.PublicKeysPEM != "":
		return []byte(cfg.PublicKeysPEM), nil
	case cfg.PublicKeyPEM != "":
		return []byte(cfg.PublicKeyPEM), nil
	default:
		b, err := os.ReadFile(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("อ่าน public key ไม่ได้: %w", err)
		}
		return b, nil
	}
}

// Issue ออก access token
//
// claim ที่ใส่: sub, email, name, roles, iat, jti, exp (+ iss/aud เมื่อตั้งค่าไว้)
//
// ⚠️ pet-service ยังไม่บังคับตรวจ iss/aud (ต้องรอให้ token เดิมหมดอายุก่อน
//
//	ไม่งั้น token ที่ผู้ใช้ถืออยู่จะใช้ไม่ได้ทันทีทั้งระบบ)
//	การใส่มาก่อนคือขั้นแรกของการปล่อยแบบ 2 เฟส
func (s *JWTTokenService) Issue(user domain.User, roles []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"name":  user.FullName,
		"roles": roles,
		"iat":   now.Unix(),
		"jti":   uuid.New().String(),
		"exp":   now.Add(s.ttl).Unix(),
	}
	if s.issuer != "" {
		claims["iss"] = s.issuer
	}
	if s.audience != "" {
		claims["aud"] = s.audience
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// kid ทำให้ผู้ตรวจเลือกคีย์ได้ถูกใบทันทีระหว่างช่วง rotate
	if s.signingKeyID != "" {
		token.Header["kid"] = s.signingKeyID
	}
	return token.SignedString(s.privateKey)
}

// Verify ตรวจลายเซ็นและอายุ แล้วคืน claims ที่ชั้น application ใช้ได้
func (s *JWTTokenService) Verify(tokenString string) (port.Claims, error) {
	token, err := jwt.Parse(tokenString, s.verificationKeyfunc)
	if err != nil || !token.Valid {
		return port.Claims{}, domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return port.Claims{}, domain.ErrTokenClaims
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return port.Claims{}, domain.ErrTokenSubject
	}

	return port.Claims{UserID: sub, Roles: domain.RolesFromClaims(claims)}, nil
}

// PublicKeyPEM คืน PEM ทุกใบที่ยอมรับ ตามรูปแบบเดิม (PEM ต่อกัน)
// service ปลายทางเอาไปใส่ JWT_PUBLIC_KEYS ได้ตรงๆ
func (s *JWTTokenService) PublicKeyPEM() []byte { return s.publicKeyBytes }

// KeyInfo สรุปว่า pod นี้เซ็นด้วยคีย์ใบไหนและยอมรับใบไหน ใช้ตรวจตอน rotate
func (s *JWTTokenService) KeyInfo() port.KeyInfo {
	accepted := make([]string, 0, len(s.acceptedKeys))
	for _, k := range s.acceptedKeys {
		accepted = append(accepted, keyID(k))
	}
	return port.KeyInfo{
		SigningKeyID:   s.signingKeyID,
		AcceptedKeyIDs: accepted,
		TokenTTL:       s.ttl.String(),
	}
}

// verificationKeyfunc เลือกคีย์ที่จะใช้ตรวจลายเซ็น
//
// รองรับ rotate แบบไม่มี downtime เหมือนฝั่ง pet-service:
//   - token ใหม่มี kid → เลือกใบที่ตรง
//   - token เก่าไม่มี kid → คืนทั้งชุดให้ไลบรารีลองทีละใบ
func (s *JWTTokenService) verificationKeyfunc(t *jwt.Token) (interface{}, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}
	if len(s.acceptedKeys) == 0 {
		return nil, fmt.Errorf("ไม่ได้ตั้งค่า public key ไว้เลย")
	}

	if kid, ok := t.Header["kid"].(string); ok && kid != "" {
		for _, k := range s.acceptedKeys {
			if keyID(k) == kid {
				return k, nil
			}
		}
		return nil, fmt.Errorf("ไม่รู้จัก kid %q", kid)
	}

	set := jwt.VerificationKeySet{}
	for _, k := range s.acceptedKeys {
		set.Keys = append(set.Keys, k)
	}
	return set, nil
}

// keyID คำนวณ kid จากตัว public key เอง (SHA-256 thumbprint ของ DER)
//
// ต้องใช้อัลกอริทึมเดียวกับ middleware.KeyID ที่ pet-service
// การคำนวณจากตัวคีย์ทำให้ทั้งสองฝั่งได้ค่าเดียวกันโดยไม่ต้องตกลงชื่อ kid กันล่วงหน้า
// และไม่มีทางตั้งค่าไม่ตรงกัน
func keyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// parsePublicKeys แยก PEM หลายบล็อกออกจากกันแล้ว parse ทีละใบ
//
// PEM ระบุขอบเขตของตัวเองอยู่แล้ว จึงต่อกันหลายบล็อกใน env ตัวเดียวได้
// โดยไม่ต้องมีตัวคั่นพิเศษ
func parsePublicKeys(raw string) ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey
	rest := []byte(raw)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("parse PEM block %q ไม่สำเร็จ: %w", block.Type, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("ไม่พบ PEM block ที่ใช้ได้")
	}
	return keys, nil
}
