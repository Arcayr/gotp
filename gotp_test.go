package gotp

import (
	"testing"
)

var (
	// testSeedBytes is a slice of test bytes for a static one-time passcode.
	testSeedBytes = []byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84}
	// testTime is a static time for testing.
	testTime = int64(100000)
)

// Tests generating a new token and ensuring its seed is of the correct length.
func TestGenerate(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Errorf("Token creation failed: %s", err.Error())
	}

	if len(token.Seed) != SeedLength {
		t.Errorf("Seed length is not prescribed length of %d, %d bytes returned.", SeedLength, len(token.Seed))
	}
}

// Tests generating a new token and ensuring its generated base32 is correct.
func TestGenerateBase32(t *testing.T) {
	correctB32 := "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2U"

	token, err := TokenFromBytes(testSeedBytes)
	if err != nil {
		t.Errorf("Token creation failed: %s", err.Error())
	}

	if token.Base32 != correctB32 {
		t.Errorf("Base32 conversion failed. Received %s instead of %s", token.Base32, correctB32)
	}
}

// Tests that the token correctly generates the appopriate one-time password.
func TestVerify(t *testing.T) {
	correctOTP := "111782"

	token, err := TokenFromBytes(testSeedBytes)
	if err != nil {
		t.Errorf("Token creation failed: %s", err.Error())
	}

	otp, err := token.GenerateTOTP(testTime)
	if err != nil {
		t.Errorf("Could not generate a one-time passcode: %s", err.Error())
	}

	if otp != correctOTP {
		t.Errorf("Generated OTP '%s' does not match test OTP '%s'", otp, correctOTP)
	}
}
