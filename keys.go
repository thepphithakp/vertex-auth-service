package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

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

// verificationKeyfunc เลือกคีย์ที่จะใช้ตรวจลายเซ็น
//
// รองรับ rotate แบบไม่มี downtime เหมือนฝั่ง pet-service:
//   - token ใหม่มี kid → เลือกใบที่ตรง
//   - token เก่าไม่มี kid → คืนทั้งชุดให้ไลบรารีลองทีละใบ
func verificationKeyfunc(t *jwt.Token) (interface{}, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}
	if len(acceptedPublicKeys) == 0 {
		return nil, fmt.Errorf("ไม่ได้ตั้งค่า public key ไว้เลย")
	}

	if kid, ok := t.Header["kid"].(string); ok && kid != "" {
		for _, k := range acceptedPublicKeys {
			if keyID(k) == kid {
				return k, nil
			}
		}
		return nil, fmt.Errorf("ไม่รู้จัก kid %q", kid)
	}

	set := jwt.VerificationKeySet{}
	for _, k := range acceptedPublicKeys {
		set.Keys = append(set.Keys, k)
	}
	return set, nil
}
