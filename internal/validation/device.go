package validation

import (
	"context"

	"forgor-server/internal/apierror"
	"forgor-server/internal/cbe"
	"forgor-server/internal/crypto"
	"forgor-server/internal/models"
	"forgor-server/internal/storage"
)

type DeviceValidator struct {
	devices *storage.DevicesRepository
}

func NewDeviceValidator(devices *storage.DevicesRepository) *DeviceValidator {
	return &DeviceValidator{devices: devices}
}

func (v *DeviceValidator) ValidateBundle(ctx context.Context, bundle *models.DeviceBundle) *apierror.APIError {
	if err := bundle.DeviceID.Validate(); err != nil {
		return apierror.InvalidDeviceID()
	}

	if len(bundle.DevicePubkeySign) != models.PublicKeyLength {
		return apierror.InvalidPublicKey()
	}
	if len(bundle.DevicePubkeyBox) != models.PublicKeyLength {
		return apierror.InvalidPublicKey()
	}
	if len(bundle.DeviceBundleSig) != models.SignatureLength {
		return apierror.InvalidSignature()
	}

	if err := crypto.VerifyDeviceID(string(bundle.DeviceID), bundle.DevicePubkeySign); err != nil {
		return apierror.BadRequest("device_id_mismatch", "device_id does not match sha256(device_pubkey_sign)")
	}

	if err := crypto.ValidateX25519PublicKey(bundle.DevicePubkeyBox); err != nil {
		return apierror.BadRequest("invalid_x25519_key", err.Error())
	}

	deviceIDBytes, err := crypto.DeviceIDToBytes(string(bundle.DeviceID))
	if err != nil {
		return apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesDeviceBundle(deviceIDBytes, bundle.DevicePubkeySign, bundle.DevicePubkeyBox)
	if err != nil {
		return apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(bundle.DevicePubkeySign, signBytes, bundle.DeviceBundleSig); err != nil {
		return apierror.InvalidSignature()
	}

	return nil
}

func (v *DeviceValidator) CheckImmutability(ctx context.Context, bundle *models.DeviceBundle) *apierror.APIError {
	existing, err := v.devices.Get(ctx, string(bundle.DeviceID))
	if err != nil {
		return apierror.InternalError()
	}

	if existing != nil {
		if !bytesEqual(existing.DevicePubkeySign, bundle.DevicePubkeySign) ||
			!bytesEqual(existing.DevicePubkeyBox, bundle.DevicePubkeyBox) ||
			!bytesEqual(existing.DeviceBundleSig, bundle.DeviceBundleSig) {
			return apierror.DuplicateDevice()
		}
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
