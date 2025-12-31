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

type SnapshotsValidator struct {
	vaults    *storage.VaultsRepository
	snapshots *storage.SnapshotsRepository
	invites   *storage.InvitesRepository
}

func NewSnapshotsValidator(
	vaults *storage.VaultsRepository,
	snapshots *storage.SnapshotsRepository,
	invites *storage.InvitesRepository,
) *SnapshotsValidator {
	return &SnapshotsValidator{
		vaults:    vaults,
		snapshots: snapshots,
		invites:   invites,
	}
}

func (v *SnapshotsValidator) ValidateSnapshot(ctx context.Context, s *models.Snapshot) (*storage.SnapshotRow, *apierror.APIError) {
	if s.MsgType != "snapshot" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'snapshot'")
	}

	if len(s.Nonce) != models.NonceLength {
		return nil, apierror.InvalidNonce()
	}
	if len(s.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(s.MemberHeadHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}
	if len(s.Ciphertext) > models.MaxSnapshotCiphertext {
		return nil, apierror.PayloadTooLarge("snapshot ciphertext exceeds maximum size")
	}
	if len(s.BaseCounterMap) > models.MaxMapLength*40 {
		return nil, apierror.PayloadTooLarge("base_counter_map exceeds maximum size")
	}
	if len(s.HeadHashMap) > models.MaxMapLength*64 {
		return nil, apierror.PayloadTooLarge("head_hash_map exceeds maximum size")
	}

	if err := s.CreatedByDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	vaultID := s.VaultID.Bytes()

	vault, err := v.vaults.Get(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if vault == nil {
		return nil, apierror.NotFound("vault")
	}

	if string(s.CreatedByDeviceID) != vault.OwnerDeviceID {
		return nil, apierror.OwnerRequired()
	}

	creator, err := v.vaults.GetMember(ctx, vaultID, string(s.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if creator == nil || !creator.IsMember {
		return nil, apierror.MembershipRequired()
	}

	head, err := v.vaults.GetMembershipHead(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if head == nil {
		return nil, apierror.BadRequest("missing_membership_head", "vault membership head is missing")
	}

	if uint64(s.MemberSeq) != head.MemberSeq {
		return nil, apierror.BadRequest("member_seq_mismatch", "member_seq does not match current membership head")
	}
	if !bytes.Equal(s.MemberHeadHash, head.MemberHeadHash) {
		return nil, apierror.BadRequest("member_head_hash_mismatch", "member_head_hash does not match current membership head")
	}

	used, err := v.invites.CheckNonceUsed(ctx, "snapshot", vaultID, string(s.CreatedByDeviceID), s.Nonce)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if used {
		return nil, apierror.BadRequest("nonce_reused", "nonce has already been used")
	}

	creatorDeviceIDBytes, err := crypto.DeviceIDToBytes(string(s.CreatedByDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesSnapshot(
		s.SnapshotID.Bytes(),
		vaultID,
		uint64(s.BaseSeq),
		uint64(s.MemberSeq),
		s.MemberHeadHash,
		s.BaseCounterMap,
		s.HeadHashMap,
		uint64(s.LamportAtSnapshot),
		uint64(s.KeyEpoch),
		s.Nonce,
		s.Ciphertext,
		creatorDeviceIDBytes,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(creator.DevicePubkeySign, signBytes, s.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	return &storage.SnapshotRow{
		SnapshotID:        s.SnapshotID.Bytes(),
		VaultID:           vaultID,
		BaseSeq:           uint64(s.BaseSeq),
		MemberSeq:         uint64(s.MemberSeq),
		MemberHeadHash:    s.MemberHeadHash,
		BaseCounterMap:    s.BaseCounterMap,
		HeadHashMap:       s.HeadHashMap,
		LamportAtSnapshot: uint64(s.LamportAtSnapshot),
		KeyEpoch:          uint64(s.KeyEpoch),
		Nonce:             s.Nonce,
		Ciphertext:        s.Ciphertext,
		Signature:         s.Signature,
		CreatedByDeviceID: string(s.CreatedByDeviceID),
		CreatedAt:         s.CreatedAt,
	}, nil
}
