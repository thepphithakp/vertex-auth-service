package port

import (
	"context"

	"vertex-auth-service/internal/domain"
)

// OAuthIdentityRepository เก็บการผูกบัญชีกับ provider ภายนอก
type OAuthIdentityRepository interface {
	// FindByProviderID หาการผูกบัญชีจาก provider + sub ของ provider
	//
	// คืน domain.ErrOAuthIdentityNotFound เมื่อยังไม่เคยผูก
	FindByProviderID(ctx context.Context, provider, providerID string) (domain.OAuthIdentity, error)

	// Create ผูก provider เข้ากับบัญชีที่มีอยู่แล้ว หรือกับบัญชีที่เพิ่งสร้าง
	Create(ctx context.Context, identity *domain.OAuthIdentity) error
}
