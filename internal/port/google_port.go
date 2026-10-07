package port

import "context"

// GoogleIdentity คือตัวตนที่ Google ยืนยันแล้ว
type GoogleIdentity struct {
	// Subject คือ sub ของ Google ใช้เป็น provider_id
	Subject string
	Email   string

	// FullName มาจาก claim "name" ว่างได้
	FullName string
}

// GoogleIdentityVerifier ตรวจ id token ของ Google
//
// รายการ client id ที่ยอมรับเป็นค่าตั้งของ adapter ไม่ใช่พารามิเตอร์
// ที่ชั้น application ต้องรู้
type GoogleIdentityVerifier interface {
	// Verify ตรวจลายเซ็นและ audience แล้วคืนตัวตนที่ยืนยันแล้ว
	//
	// คืน domain.ErrGoogleTokenInvalid เมื่อลายเซ็นหรืออายุไม่ผ่าน,
	// domain.ErrGoogleAudienceInvalid เมื่อ client id ไม่อยู่ในรายการที่ยอมรับ,
	// domain.ErrGoogleEmailMissing เมื่อบัญชีไม่มีอีเมล
	Verify(ctx context.Context, idToken string) (GoogleIdentity, error)
}
