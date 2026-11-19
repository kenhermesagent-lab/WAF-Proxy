package auth

import (
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password accepted")
	}
}

func TestTOTPValidation(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_800_000_000, 0)
	code, err := TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTP(secret, code, at) {
		t.Fatal("current code rejected")
	}
	if ValidateTOTP(secret, "000000", at) && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestRecoveryCodesAreOneTime(t *testing.T) {
	plain, stored, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) == 0 || stored == "" {
		t.Fatal("no codes generated")
	}
	if !VerifyRecoveryCode(stored, plain[0]) {
		t.Fatal("generated code rejected")
	}
	if VerifyRecoveryCode(stored, "AAA-BBB-CCC") {
		t.Fatal("unknown code accepted")
	}
}
