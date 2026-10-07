package domain

import "errors"

// Sentinel error ที่ชั้น application กับ adapter ใช้คุยกัน
//
// ชั้น adapter คืน error เหล่านี้แทน error ของไลบรารี (gorm, jwt, idtoken)
// เพื่อให้ชั้น application ตัดสินใจได้โดยไม่ต้องรู้จักไลบรารีไหนเลย
var (
	// ErrUserNotFound ไม่พบผู้ใช้ — รวมกรณี id ที่ส่งมาไม่ใช่ UUID ที่ใช้ได้
	//
	// รวมสองกรณีไว้ด้วยกันโดยตั้งใจ: โค้ดเดิมส่งสตริงดิบเข้า query
	// แล้ว PostgreSQL ปฏิเสธ ทำให้ได้ 404 เหมือนกรณีไม่มีแถว
	ErrUserNotFound = errors.New("ไม่พบผู้ใช้")

	// ErrEmailExists อีเมลนี้มีบัญชีอยู่แล้ว
	ErrEmailExists = errors.New("อีเมลนี้ถูกใช้แล้ว")

	// ErrOAuthIdentityNotFound ยังไม่มีการผูกบัญชีกับ provider นี้
	ErrOAuthIdentityNotFound = errors.New("ไม่พบการผูกบัญชีกับ provider นี้")

	// ErrBootstrapAdminNotFound อีเมลนี้ไม่ได้อยู่ในรายการ bootstrap_admins
	//
	// เป็นกรณีปกติ ไม่ใช่ความผิดพลาด
	ErrBootstrapAdminNotFound = errors.New("ไม่ได้อยู่ในรายการ bootstrap_admins")
)

// Sentinel error ของการตรวจ token
//
// แยกเป็นสามตัวเพราะข้อความที่ตอบผู้เรียกต่างกัน (ดู handler middleware)
var (
	ErrTokenInvalid = errors.New("token ใช้ไม่ได้หรือหมดอายุ")
	ErrTokenClaims  = errors.New("claims ใน token ใช้ไม่ได้")
	ErrTokenSubject = errors.New("sub ใน token ใช้ไม่ได้")
)

// Sentinel error ของการตรวจ id token ฝั่ง Google
//
// ทั้งสามตัวตอบสถานะต่างกัน จึงต้องแยกจากกันให้ชัด
var (
	ErrGoogleTokenInvalid    = errors.New("Google id token ใช้ไม่ได้")
	ErrGoogleAudienceInvalid = errors.New("Google client id audience ใช้ไม่ได้")
	ErrGoogleEmailMissing    = errors.New("บัญชี Google ไม่มีอีเมล")
)
