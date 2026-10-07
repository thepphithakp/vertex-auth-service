// Package google ตรวจ id token ของ Google ผ่าน idtoken.Validate
//
// SDK ของ Google ไม่รั่วออกจากแพ็กเกจนี้ — ชั้น application เห็นแค่
// port.GoogleIdentityVerifier
package google

import (
	"context"

	"google.golang.org/api/idtoken"

	"vertex-auth-service/internal/domain"
	"vertex-auth-service/internal/port"
)

// Client id ที่ยอมรับ — เดิม hardcode อยู่ใน handleGoogleLogin ของ main.go
//
// ย้ายมาไว้ที่ adapter เพราะเป็นรายละเอียดของ "การคุยกับ Google"
// ไม่ใช่กฎของ application — ชั้น application ไม่ควรรู้จักค่าพวกนี้เลย
const (
	ClientIDIOS = "565361629384-nm0k3gs5affdnva1gjlfb2b9musj0614.apps.googleusercontent.com"
	ClientIDWeb = "565361629384-lre3e35dhoj151akegf1bskv38st9oe3.apps.googleusercontent.com"
)

// DefaultAllowedAudiences คือชุดที่ production ใช้อยู่
//
// คืน slice ใหม่ทุกครั้งเพื่อไม่ให้ผู้เรียกแก้ค่าที่แชร์กัน
func DefaultAllowedAudiences() []string {
	return []string{ClientIDIOS, ClientIDWeb}
}

// Verifier implements port.GoogleIdentityVerifier
type Verifier struct {
	// allowed เก็บเป็น set เพื่อให้ตรวจ audience ได้ในขั้นตอนเดียว
	// เหมือน map validClients ของโค้ดเดิม
	allowed map[string]bool
}

// NewGoogleVerifier รับรายการ client id ที่ยอมรับเข้ามาเป็นค่าตั้ง
func NewGoogleVerifier(allowedAudiences []string) *Verifier {
	allowed := make(map[string]bool, len(allowedAudiences))
	for _, aud := range allowedAudiences {
		allowed[aud] = true
	}
	return &Verifier{allowed: allowed}
}

// Verify ตรวจลายเซ็นแล้วตรวจ audience ตามลำดับเดิมของ handleGoogleLogin
//
// ⚠️ ส่ง audience ว่างให้ idtoken.Validate เหมือนเดิม แล้วตรวจ audience
//
//	ด้วยตัวเองทีหลัง ไม่ใช่ปล่อยให้ไลบรารีตรวจให้ เพราะไลบรารีรับได้
//	ทีละค่าเดียว แต่ที่นี่ต้องยอมรับสองค่า (iOS กับ Web)
//	การตรวจเองจึงเป็นเงื่อนไขที่ทำให้รองรับทั้งสอง client ได้
func (v *Verifier) Verify(ctx context.Context, idToken string) (port.GoogleIdentity, error) {
	payload, err := idtoken.Validate(ctx, idToken, "")
	if err != nil {
		return port.GoogleIdentity{}, domain.ErrGoogleTokenInvalid
	}

	if !v.allowed[payload.Audience] {
		return port.GoogleIdentity{}, domain.ErrGoogleAudienceInvalid
	}

	email, ok := payload.Claims["email"].(string)
	if !ok || email == "" {
		return port.GoogleIdentity{}, domain.ErrGoogleEmailMissing
	}

	// claim "name" ว่างได้ — ผู้เรียกเป็นฝ่ายตัดสินว่าจะใช้ค่าจาก request แทนไหม
	fullName, _ := payload.Claims["name"].(string)

	return port.GoogleIdentity{
		Subject:  payload.Subject,
		Email:    email,
		FullName: fullName,
	}, nil
}
