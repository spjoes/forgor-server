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

type KeyUpdatesValidator struct {
	vaults     *storage.VaultsRepository
	keyUpdates *storage.KeyUpdatesRepository
	invites    *storage.InvitesRepository
}

func NewKeyUpdatesValidator(
	vaults *storage.VaultsRepository,
	keyUpdates *storage.KeyUpdatesRepository,
	invites *storage.InvitesRepository,
) *KeyUpdatesValidator {
	return &KeyUpdatesValidator{
		vaults:     vaults,
		keyUpdates: keyUpdates,
		invites:    invites,
	}
}

func (v *KeyUpdatesValidator) ValidateKeyUpdate(ctx context.Context, ku *models.KeyUpdate) (*storage.KeyUpdateRow, *apierror.APIError) {
	if ku.MsgType != "key_update" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'key_update'")
	}

	if len(ku.Nonce) != models.NonceLength {
		return nil, apierror.InvalidNonce()
	}
	if len(ku.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(ku.MemberHeadHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}
	if len(ku.WrappedPayload) > models.MaxWrappedPayload {
		return nil, apierror.PayloadTooLarge("wrapped_payload exceeds maximum size")
	}

	if err := ku.TargetDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	if err := ku.CreatedByDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	vaultID := ku.VaultID.Bytes()

	vault, err := v.vaults.Get(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if vault == nil {
		return nil, apierror.NotFound("vault")
	}

	if string(ku.CreatedByDeviceID) != vault.OwnerDeviceID {
		return nil, apierror.OwnerRequired()
	}

	creator, err := v.vaults.GetMember(ctx, vaultID, string(ku.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if creator == nil || !creator.IsMember {
		return nil, apierror.MembershipRequired()
	}

	isMember, err := v.vaults.IsMember(ctx, vaultID, string(ku.TargetDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if !isMember {
		return nil, apierror.BadRequest("target_not_member", "target_device_id is not a current member")
	}

	head, err := v.vaults.GetMembershipHead(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if head == nil {
		return nil, apierror.BadRequest("missing_membership_head", "vault membership head is missing")
	}

	if uint64(ku.MemberSeq) != head.MemberSeq {
		return nil, apierror.BadRequest("member_seq_mismatch", "member_seq does not match current membership head")
	}
	if !bytes.Equal(ku.MemberHeadHash, head.MemberHeadHash) {
		return nil, apierror.BadRequest("member_head_hash_mismatch", "member_head_hash does not match current membership head")
	}

	exists, err := v.keyUpdates.CheckExists(ctx, vaultID, uint64(ku.KeyEpoch), string(ku.TargetDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if exists {
		return nil, apierror.Conflict("key update for this epoch and target already exists")
	}

	used, err := v.invites.CheckNonceUsed(ctx, "key_update", vaultID, string(ku.CreatedByDeviceID), ku.Nonce)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if used {
		return nil, apierror.BadRequest("nonce_reused", "nonce has already been used")
	}

	targetDeviceIDBytes, err := crypto.DeviceIDToBytes(string(ku.TargetDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	creatorDeviceIDBytes, err := crypto.DeviceIDToBytes(string(ku.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesKeyUpdate(
		ku.KeyUpdateID.Bytes(),
		vaultID,
		uint64(ku.MemberSeq),
		ku.MemberHeadHash,
		targetDeviceIDBytes,
		uint64(ku.KeyEpoch),
		ku.Nonce,
		ku.WrappedPayload,
		creatorDeviceIDBytes,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(creator.DevicePubkeySign, signBytes, ku.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	return &storage.KeyUpdateRow{
		KeyUpdateID:       ku.KeyUpdateID.Bytes(),
		VaultID:           vaultID,
		MemberSeq:         uint64(ku.MemberSeq),
		MemberHeadHash:    ku.MemberHeadHash,
		TargetDeviceID:    string(ku.TargetDeviceID),
		KeyEpoch:          uint64(ku.KeyEpoch),
		Nonce:             ku.Nonce,
		WrappedPayload:    ku.WrappedPayload,
		CreatedByDeviceID: string(ku.CreatedByDeviceID),
		Signature:         ku.Signature,
		CreatedAt:         ku.CreatedAt,
	}, nil
}

func (v *KeyUpdatesValidator) ValidateKeyUpdateAck(ctx context.Context, ack *models.KeyUpdateAck) (*storage.KeyUpdateAckRow, *apierror.APIError) {
	if ack.MsgType != "key_update_ack" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'key_update_ack'")
	}

	if len(ack.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(ack.MemberHeadHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}

	if err := ack.DeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	vaultID := ack.VaultID.Bytes()

	member, err := v.vaults.GetMember(ctx, vaultID, string(ack.DeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if member == nil || !member.IsMember {
		return nil, apierror.MembershipRequired()
	}

	head, err := v.vaults.GetMembershipHead(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if head == nil {
		return nil, apierror.BadRequest("missing_membership_head", "vault membership head is missing")
	}

	if uint64(ack.MemberSeq) != head.MemberSeq {
		return nil, apierror.BadRequest("member_seq_mismatch", "member_seq does not match current membership head")
	}
	if !bytes.Equal(ack.MemberHeadHash, head.MemberHeadHash) {
		return nil, apierror.BadRequest("member_head_hash_mismatch", "member_head_hash does not match current membership head")
	}

	deviceIDBytes, err := crypto.DeviceIDToBytes(string(ack.DeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesKeyUpdateAck(
		vaultID,
		deviceIDBytes,
		uint64(ack.KeyEpoch),
		uint64(ack.MemberSeq),
		ack.MemberHeadHash,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(member.DevicePubkeySign, signBytes, ack.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	return &storage.KeyUpdateAckRow{
		VaultID:        vaultID,
		KeyEpoch:       uint64(ack.KeyEpoch),
		DeviceID:       string(ack.DeviceID),
		MemberSeq:      uint64(ack.MemberSeq),
		MemberHeadHash: ack.MemberHeadHash,
		Signature:      ack.Signature,
		CreatedAt:      ack.CreatedAt,
	}, nil
}
