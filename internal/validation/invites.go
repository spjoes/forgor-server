package validation

import (
	"bytes"
	"context"

	"forgor-server/internal/apierror"
	"forgor-server/internal/cbe"
	"forgor-server/internal/crypto"
	"forgor-server/internal/models"
	"forgor-server/internal/storage"
)

type InvitesValidator struct {
	vaults  *storage.VaultsRepository
	invites *storage.InvitesRepository
	devices *storage.DevicesRepository
}

func NewInvitesValidator(
	vaults *storage.VaultsRepository,
	invites *storage.InvitesRepository,
	devices *storage.DevicesRepository,
) *InvitesValidator {
	return &InvitesValidator{
		vaults:  vaults,
		invites: invites,
		devices: devices,
	}
}

func (v *InvitesValidator) ValidateInvite(ctx context.Context, invite *models.Invite) (*storage.InviteRow, *apierror.APIError) {
	if invite.MsgType != "invite" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'invite'")
	}

	if len(invite.Nonce) != models.NonceLength {
		return nil, apierror.InvalidNonce()
	}
	if len(invite.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(invite.WrappedPayload) > models.MaxWrappedPayload {
		return nil, apierror.PayloadTooLarge("wrapped_payload exceeds maximum size")
	}
	if len(invite.TargetDevicePubkeySign) != models.PublicKeyLength {
		return nil, apierror.InvalidPublicKey()
	}
	if len(invite.TargetDevicePubkeyBox) != models.PublicKeyLength {
		return nil, apierror.InvalidPublicKey()
	}
	if len(invite.TargetDeviceBundleSig) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}

	if err := invite.TargetDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	if err := invite.CreatedByDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	vaultID := invite.VaultID.Bytes()

	vault, err := v.vaults.Get(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if vault == nil {
		return nil, apierror.NotFound("vault")
	}

	creator, err := v.vaults.GetMember(ctx, vaultID, string(invite.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if creator == nil || !creator.IsMember {
		return nil, apierror.MembershipRequired()
	}

	if err := crypto.VerifyDeviceID(string(invite.TargetDeviceID), invite.TargetDevicePubkeySign); err != nil {
		return nil, apierror.BadRequest("target_device_id_mismatch", "target_device_id does not match sha256(target_device_pubkey_sign)")
	}

	targetDeviceIDBytes, err := crypto.DeviceIDToBytes(string(invite.TargetDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	targetBundleSignBytes, err := cbe.SignBytesDeviceBundle(targetDeviceIDBytes, invite.TargetDevicePubkeySign, invite.TargetDevicePubkeyBox)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(invite.TargetDevicePubkeySign, targetBundleSignBytes, invite.TargetDeviceBundleSig); err != nil {
		return nil, apierror.BadRequest("invalid_target_bundle_sig", "target bundle signature verification failed")
	}

	used, err := v.invites.CheckNonceUsed(ctx, "invite", vaultID, string(invite.CreatedByDeviceID), invite.Nonce)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if used {
		return nil, apierror.BadRequest("nonce_reused", "nonce has already been used")
	}

	creatorDeviceIDBytes, err := crypto.DeviceIDToBytes(string(invite.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesInvite(
		invite.InviteID.Bytes(),
		vaultID,
		targetDeviceIDBytes,
		invite.TargetDevicePubkeySign,
		invite.TargetDevicePubkeyBox,
		invite.TargetDeviceBundleSig,
		invite.Nonce,
		invite.WrappedPayload,
		creatorDeviceIDBytes,
		invite.SingleUse,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(creator.DevicePubkeySign, signBytes, invite.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	return &storage.InviteRow{
		InviteID:              invite.InviteID.Bytes(),
		VaultID:               vaultID,
		TargetDeviceID:        string(invite.TargetDeviceID),
		TargetDevicePubkeySign: invite.TargetDevicePubkeySign,
		TargetDevicePubkeyBox:  invite.TargetDevicePubkeyBox,
		TargetDeviceBundleSig:  invite.TargetDeviceBundleSig,
		Nonce:                 invite.Nonce,
		WrappedPayload:        invite.WrappedPayload,
		CreatedByDeviceID:     string(invite.CreatedByDeviceID),
		SingleUse:             invite.SingleUse,
		Used:                  false,
		Signature:             invite.Signature,
		CreatedAt:             invite.CreatedAt,
	}, nil
}

func (v *InvitesValidator) ValidateInviteClaim(ctx context.Context, claim *models.InviteClaim) (*storage.InviteClaimRow, *apierror.APIError) {
	if claim.MsgType != "invite_claim" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'invite_claim'")
	}

	if len(claim.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}

	if err := claim.DeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	invite, err := v.invites.Get(ctx, claim.InviteID.Bytes())
	if err != nil {
		return nil, apierror.InternalError()
	}
	if invite == nil {
		return nil, apierror.NotFound("invite")
	}

	if !bytes.Equal(invite.VaultID, claim.VaultID.Bytes()) {
		return nil, apierror.BadRequest("vault_mismatch", "vault_id does not match invite")
	}

	if invite.TargetDeviceID != string(claim.DeviceID) {
		return nil, apierror.BadRequest("device_mismatch", "device_id does not match invite target")
	}

	device, err := v.devices.Get(ctx, string(claim.DeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if device == nil {
		return nil, apierror.NotFound("device")
	}

	deviceIDBytes, err := crypto.DeviceIDToBytes(string(claim.DeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesInviteClaim(claim.InviteID.Bytes(), claim.VaultID.Bytes(), deviceIDBytes)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(device.DevicePubkeySign, signBytes, claim.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	return &storage.InviteClaimRow{
		InviteID:  claim.InviteID.Bytes(),
		VaultID:   claim.VaultID.Bytes(),
		DeviceID:  string(claim.DeviceID),
		ClaimSig:  claim.Signature,
		CreatedAt: claim.CreatedAt,
	}, nil
}
