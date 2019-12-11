// Package gotp is a Go library implementing the RFC6238 time-based one-time
// password algorithm, and RFC4226 HMAC-based one-time password algorithm.
// RFC6238 is based off RFC4226, however it uses a counter step of increments
// of 30 seconds since 1970-01-01T00:00:00Z.
package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

var (
	// The step to use. RFC6238 dictates a step of 30 seconds, however some
	// implementations use alternative steps.
	StepSeconds = 30
	// SeedLength is the length of the HMAC secret, or seed.
	// Usually 10 or so.
	SeedLength int = 20
	// TokenLength is the length of the generated TOTP.
	// Usually 6, sometimes 8.
	TokenLength = 6
)

// runeCharacters is a slice of available runes for secret generation.
// This var is not modifiable outside of the library.
var runeCharacters = []rune("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")

// Token is the core one-time password struct.
// It is naive, and does not store information about its counter step to
// facilitate simple construction of time-based one-time password.
type Token struct {
	Seed   []byte
	Base32 string
}

// GenerateOTP generates a single six-digit OTP based on the OTP's seed and
// the counter factor.
func (t *Token) GenerateOTP(counterBytes []byte) (string, error) {
	if len(t.Seed) == 0 {
		return "", errors.New("OTP has no seed.")
	}

	if len(counterBytes) == 0 {
		return "", errors.New("Counter is nil or otherwise malformed.")
	}

	// Generate HMAC from counter factor.
	hmacer := hmac.New(sha1.New, t.Seed)
	hmacer.Write(counterBytes)
	hmac := hmacer.Sum(nil)

	// Generate OTP.
	// Source: https://tools.ietf.org/html/rfc4226#section-5.4
	offset := int(hmac[len(hmac)-1] & 0xF)
	otp := ((int(hmac[offset]) & 0x7F) << 24) |
		((int(hmac[offset+1] & 0xFF)) << 16) |
		((int(hmac[offset+2] & 0xFF)) << 8) |
		(int(hmac[offset+3]) & 0xFF)

	otp = otp % int(math.Pow10(TokenLength))

	// Left-pad with zeroes if the value is less than six characters long.
	otpString := fmt.Sprintf(fmt.Sprintf("%%0%dd", TokenLength), otp)

	return otpString, nil
}

// GenerateTOTP generates an OTP value based on the `genTime` provided time.
func (t *Token) GenerateTOTP(genTime int64) (string, error) {
	timeStep := genTime / int64(StepSeconds)
	timeBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeBytes[i] = byte(timeStep & 0xff)
		timeStep = timeStep >> 8
	}

	return t.GenerateOTP(timeBytes)
}

// VerifyChallenge verifies the `challenge` password.
// If `drift` is true, it will verify the challenge against a 90-second window
// of TOTP generation to protect against clock drift denial of service,
// through no fault of the user.
func (t *Token) VerifyChallenge(challenge string, drift bool) bool {
	otps := []string{}
	steps := []int{0}

	if drift == true {
		steps = append(steps, []int{(-1 * StepSeconds), StepSeconds}...)
	}

	for _, step := range steps {
		genTime := time.Now().Unix() + int64(step)
		otp, err := t.GenerateTOTP(genTime)
		if err != nil {
			return false
		}

		otps = append(otps, otp)
	}

	for _, otp := range otps {
		if otp == challenge {
			return true
		}
	}

	return false
}

// TokenFromBytes generates a new OTP from an existing seed.
func TokenFromBytes(seedBytes []byte) (*Token, error) {
	token := &Token{
		Seed:   seedBytes,
		Base32: strings.ToUpper(base32.StdEncoding.EncodeToString(seedBytes)),
	}

	return token, nil
}

// NewToken generates a new OTP token with a random seed.
func NewToken() (*Token, error) {
	rand.Seed(time.Now().UnixNano())
	seedRunes := make([]rune, SeedLength)

	for i := range seedRunes {
		seedRunes[i] = runeCharacters[rand.Intn(len(runeCharacters))]
	}

	seedBytes := []byte(string(seedRunes))

	return TokenFromBytes(seedBytes)
}
