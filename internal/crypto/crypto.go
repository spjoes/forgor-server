package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func ComputeDeviceID(pubkeySign []byte) (string, error) {
	if len(pubkeySign) != ed25519.PublicKeySize {
		return "", fmt.Errorf("pubkey_sign must be %d bytes", ed25519.PublicKeySize)
	}
	hash := sha256.Sum256(pubkeySign)
	return hex.EncodeToString(hash[:]), nil
}

func ComputeDeviceIDBytes(pubkeySign []byte) ([]byte, error) {
	if len(pubkeySign) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey_sign must be %d bytes", ed25519.PublicKeySize)
	}
	hash := sha256.Sum256(pubkeySign)
	return hash[:], nil
}

func VerifyDeviceID(deviceIDHex string, pubkeySign []byte) error {
	expected, err := ComputeDeviceID(pubkeySign)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(deviceIDHex), []byte(expected)) != 1 {
		return fmt.Errorf("device_id does not match pubkey_sign hash")
	}
	return nil
}

func VerifySignature(pubkey, message, signature []byte) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkey, message, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ValidateX25519PublicKey(pubkey []byte) error {
	if len(pubkey) != 32 {
		return fmt.Errorf("X25519 public key must be 32 bytes")
	}

	// I stole this from the ol' interwebs. Idk what this does but im pretty sure it fixes my issue.
	// I hope this works. theres so many numbers and letters and im tired and UGHHHHHHH
	// (im putting this here because I dont want to take credit for this monstrosity of code)

	smallOrderPoints := [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
		{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	}

	for _, point := range smallOrderPoints {
		if subtle.ConstantTimeCompare(pubkey, point) == 1 {
			return fmt.Errorf("X25519 public key is a small-order point")
		}
	}

	testScalar := make([]byte, 32)
	testScalar[0] = 1
	result, err := curve25519.X25519(testScalar, pubkey)
	if err != nil {
		return fmt.Errorf("X25519 computation failed: %w", err)
	}

	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("X25519 public key produces all-zero shared secret")
	}

	return nil
}

func SHA256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func DeviceIDToBytes(deviceIDHex string) ([]byte, error) {
	if len(deviceIDHex) != 64 {
		return nil, fmt.Errorf("device_id must be 64 hex characters")
	}
	return hex.DecodeString(deviceIDHex)
}
