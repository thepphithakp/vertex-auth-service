package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestKeyID_Stable(t *testing.T) {
	k := genKey(t)
	if a, b := keyID(&k.PublicKey), keyID(&k.PublicKey); a == "" || a != b {
		t.Fatalf("kid ต้องคงที่: %q vs %q", a, b)
	}
	if keyID(&genKey(t).PublicKey) == keyID(&k.PublicKey) {
		t.Fatal("คีย์คนละใบต้องได้ kid ต่างกัน")
	}
}

func TestParsePublicKeys(t *testing.T) {
	k1, k2 := genKey(t), genKey(t)

	t.Run("ใบเดียว", func(t *testing.T) {
		keys, err := parsePublicKeys(pubPEM(t, k1))
		if err != nil || len(keys) != 1 {
			t.Fatalf("keys=%d err=%v", len(keys), err)
		}
	})

	// รูปแบบที่ใช้ตอน rotate: PEM สองบล็อกต่อกันใน env เดียว
	t.Run("สองใบต่อกัน", func(t *testing.T) {
		keys, err := parsePublicKeys(pubPEM(t, k1) + pubPEM(t, k2))
		if err != nil || len(keys) != 2 {
			t.Fatalf("keys=%d err=%v", len(keys), err)
		}
		if keyID(keys[0]) == keyID(keys[1]) {
			t.Fatal("ต้องได้คนละใบ")
		}
	})

	t.Run("มีช่องว่างและบรรทัดเปล่าคั่น", func(t *testing.T) {
		keys, err := parsePublicKeys("\n\n" + pubPEM(t, k1) + "\n\n" + pubPEM(t, k2) + "\n")
		if err != nil || len(keys) != 2 {
			t.Fatalf("keys=%d err=%v", len(keys), err)
		}
	})

	t.Run("ค่าที่ไม่ใช่ PEM → error", func(t *testing.T) {
		if _, err := parsePublicKeys("ไม่ใช่คีย์"); err == nil {
			t.Fatal("ต้องคืน error")
		}
	})
}

// TestVerificationKeyfunc_Rotation ยืนยันว่าระหว่าง rotate
// token ที่เซ็นด้วยคีย์เก่าและยังไม่หมดอายุ ยัง verify ผ่าน
func TestVerificationKeyfunc_Rotation(t *testing.T) {
	oldKey, newKey := genKey(t), genKey(t)
	acceptedPublicKeys = []*rsa.PublicKey{&oldKey.PublicKey, &newKey.PublicKey}
	t.Cleanup(func() { acceptedPublicKeys = nil; signingKeyID = "" })

	makeToken := func(k *rsa.PrivateKey, kid string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": uuid.NewString(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		if kid != "" {
			tok.Header["kid"] = kid
		}
		s, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	cases := []struct {
		name  string
		token string
		valid bool
	}{
		{"คีย์เก่า ไม่มี kid (token ที่ออกก่อน rotate)", makeToken(oldKey, ""), true},
		{"คีย์เก่า มี kid", makeToken(oldKey, keyID(&oldKey.PublicKey)), true},
		{"คีย์ใหม่ มี kid", makeToken(newKey, keyID(&newKey.PublicKey)), true},
		{"kid ไม่รู้จัก", makeToken(newKey, "ไม่มีจริง"), false},
		{"kid ชี้คีย์หนึ่ง เซ็นด้วยอีกคีย์", makeToken(oldKey, keyID(&newKey.PublicKey)), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := jwt.Parse(tc.token, verificationKeyfunc)
			got := err == nil && tok.Valid
			if got != tc.valid {
				t.Fatalf("valid = %v ต้องการ %v (err=%v)", got, tc.valid, err)
			}
		})
	}

	t.Run("คีย์ที่ไม่อยู่ในรายการ", func(t *testing.T) {
		rogue := genKey(t)
		if tok, err := jwt.Parse(makeToken(rogue, ""), verificationKeyfunc); err == nil && tok.Valid {
			t.Fatal("คีย์ที่ไม่ได้ตั้งค่าไว้ต้องถูกปฏิเสธ")
		}
	})
}

// หลัง rotate เสร็จ เอาคีย์เก่าออกแล้ว token เก่าต้องใช้ไม่ได้
func TestVerificationKeyfunc_AfterRotation(t *testing.T) {
	oldKey, newKey := genKey(t), genKey(t)
	acceptedPublicKeys = []*rsa.PublicKey{&newKey.PublicKey}
	t.Cleanup(func() { acceptedPublicKeys = nil })

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": uuid.NewString(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	s, _ := tok.SignedString(oldKey)
	if parsed, err := jwt.Parse(s, verificationKeyfunc); err == nil && parsed.Valid {
		t.Fatal("token ที่เซ็นด้วยคีย์เก่าต้องใช้ไม่ได้หลังเอาคีย์ออกแล้ว")
	}
}
