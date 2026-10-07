package repository

import (
	"context"

	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/domain"
)

// GORMOAuthIdentityRepository implements port.OAuthIdentityRepository
type GORMOAuthIdentityRepository struct {
	db *gorm.DB
}

func NewGORMOAuthIdentityRepository(db *gorm.DB) *GORMOAuthIdentityRepository {
	return &GORMOAuthIdentityRepository{db: db}
}

func (r *GORMOAuthIdentityRepository) FindByProviderID(
	ctx context.Context, provider, providerID string,
) (domain.OAuthIdentity, error) {
	var row model.OAuthIdentity
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_id = ?", provider, providerID).
		First(&row).Error
	if err != nil {
		return domain.OAuthIdentity{}, domain.ErrOAuthIdentityNotFound
	}
	return row.ToDomain(), nil
}

func (r *GORMOAuthIdentityRepository) Create(ctx context.Context, identity *domain.OAuthIdentity) error {
	row := model.OAuthIdentityFromDomain(*identity)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return err
	}
	*identity = row.ToDomain()
	return nil
}
