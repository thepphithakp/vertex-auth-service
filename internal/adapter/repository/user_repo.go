// Package repository คือ output adapter ที่คุยกับ PostgreSQL ผ่าน GORM
package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"vertex-auth-service/internal/adapter/repository/model"
	"vertex-auth-service/internal/domain"
)

// GORMUserRepository implements port.UserRepository
type GORMUserRepository struct {
	db *gorm.DB
}

func NewGORMUserRepository(db *gorm.DB) *GORMUserRepository {
	return &GORMUserRepository{db: db}
}

func (r *GORMUserRepository) Create(ctx context.Context, user *domain.User) error {
	row := model.UserFromDomain(*user)
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return err
	}
	// GORM ใส่ created_at/updated_at ให้ตอน insert — ต้องส่งกลับไปด้วย
	// เพราะ handler คืน user ก้อนนี้ลง response
	*user = row.ToDomain()
	return nil
}

func (r *GORMUserRepository) FindByEmail(ctx context.Context, email string) (domain.User, error) {
	var row model.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&row).Error; err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}
	return row.ToDomain(), nil
}

func (r *GORMUserRepository) FindByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	var row model.User
	if err := r.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return domain.User{}, domain.ErrUserNotFound
	}
	return row.ToDomain(), nil
}

func (r *GORMUserRepository) Save(ctx context.Context, user *domain.User) error {
	row := model.UserFromDomain(*user)
	if err := r.db.WithContext(ctx).Save(&row).Error; err != nil {
		return fmt.Errorf("บันทึกผู้ใช้ %s ไม่สำเร็จ: %w", user.ID, err)
	}
	*user = row.ToDomain()
	return nil
}

func (r *GORMUserRepository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", id).
		Update("email_verified", true).Error
}

func (r *GORMUserRepository) FindAll(ctx context.Context) ([]domain.User, error) {
	var rows []model.User
	if err := r.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	return toDomainUsers(rows), nil
}

func (r *GORMUserRepository) List(ctx context.Context, search string, limit int) ([]domain.User, error) {
	q := r.db.WithContext(ctx).Order("created_at desc")
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("email ILIKE ? OR full_name ILIKE ?", like, like)
	}

	var rows []model.User
	if err := q.Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	return toDomainUsers(rows), nil
}

func toDomainUsers(rows []model.User) []domain.User {
	users := make([]domain.User, len(rows))
	for i := range rows {
		users[i] = rows[i].ToDomain()
	}
	return users
}
