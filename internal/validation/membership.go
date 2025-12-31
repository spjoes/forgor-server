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

type MembershipValidator struct {
	vaults       *storage.VaultsRepository
	memberEvents *storage.MemberEventsRepository
	invites      *storage.InvitesRepository
	devices      *storage.DevicesRepository
}

func NewMembershipValidator(
	vaults *storage.VaultsRepository,
	memberEvents *storage.MemberEventsRepository,
	invites *storage.InvitesRepository,
	devices *storage.DevicesRepository,
) *MembershipValidator {
	return &MembershipValidator{
		vaults:       vaults,
		memberEvents: memberEvents,
		invites:      invites,
		devices:      devices,
	}
}

func (v *MembershipValidator) ValidateMemberAdd(ctx context.Context, event *models.MemberEvent) (*storage.MemberEventRow, *apierror.APIError) {
	if event.MsgType != "member_add" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected member_add")
	}

	if len(event.PrevHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}
	if len(event.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(event.SubjectPubkeySign) != models.PublicKeyLength {
		return nil, apierror.InvalidPublicKey()
	}
	if len(event.SubjectPubkeyBox) != models.PublicKeyLength {
		return nil, apierror.InvalidPublicKey()
	}
	if len(event.SubjectBundleSig) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(event.ClaimSig) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}

	if err := event.ActorDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	if err := event.SubjectDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	if err := crypto.VerifyDeviceID(string(event.SubjectDeviceID), event.SubjectPubkeySign); err != nil {
		return nil, apierror.BadRequest("subject_device_id_mismatch", "subject_device_id does not match sha256(subject_pubkey_sign)")
	}

	subjectDeviceIDBytes, err := crypto.DeviceIDToBytes(string(event.SubjectDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	subjectBundleSignBytes, err := cbe.SignBytesDeviceBundle(subjectDeviceIDBytes, event.SubjectPubkeySign, event.SubjectPubkeyBox)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(event.SubjectPubkeySign, subjectBundleSignBytes, event.SubjectBundleSig); err != nil {
		return nil, apierror.BadRequest("invalid_subject_bundle_sig", "subject bundle signature verification failed")
	}

	vaultID := event.VaultID.Bytes()
	vault, err := v.vaults.Get(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}

	memberSeq := uint64(event.MemberSeq)
	isGenesis := memberSeq == 1

	if isGenesis {
		if vault != nil {
			return nil, apierror.Conflict("vault already exists")
		}

		if event.ActorDeviceID != event.SubjectDeviceID {
			return nil, apierror.BadRequest("genesis_actor_mismatch", "genesis member_add must have actor_device_id == subject_device_id")
		}

		if !bytes.Equal(event.PrevHash, models.Zero32) {
			return nil, apierror.BadRequest("genesis_prev_hash", "genesis member_add must have prev_hash = zero")
		}
	} else {
		if vault == nil {
			return nil, apierror.NotFound("vault")
		}

		if string(event.ActorDeviceID) != vault.OwnerDeviceID {
			return nil, apierror.OwnerRequired()
		}

		head, err := v.vaults.GetMembershipHead(ctx, vaultID)
		if err != nil {
			return nil, apierror.InternalError()
		}
		if head == nil {
			return nil, apierror.BadRequest("missing_membership_head", "vault exists but membership head is missing")
		}

		if memberSeq != head.MemberSeq+1 {
			return nil, apierror.MembershipChainBroken()
		}
		if !bytes.Equal(event.PrevHash, head.MemberHeadHash) {
			return nil, apierror.MembershipChainBroken()
		}

		invite, err := v.invites.Get(ctx, event.InviteID.Bytes())
		if err != nil {
			return nil, apierror.InternalError()
		}
		if invite == nil {
			return nil, apierror.NotFound("invite")
		}

		if !bytes.Equal(invite.VaultID, vaultID) {
			return nil, apierror.BadRequest("invite_vault_mismatch", "invite is for a different vault")
		}
		if invite.TargetDeviceID != string(event.SubjectDeviceID) {
			return nil, apierror.BadRequest("invite_target_mismatch", "invite is for a different device")
		}
		if invite.SingleUse && invite.Used {
			return nil, apierror.InviteAlreadyUsed()
		}

		claim, err := v.invites.GetClaim(ctx, invite.InviteID, string(event.SubjectDeviceID))
		if err != nil {
			return nil, apierror.InternalError()
		}
		if claim == nil {
			return nil, apierror.BadRequest("missing_invite_claim", "invite has not been claimed")
		}

		if !bytes.Equal(claim.ClaimSig, event.ClaimSig) {
			return nil, apierror.BadRequest("claim_sig_mismatch", "claim_sig does not match stored claim")
		}

		claimSignBytes, err := cbe.SignBytesInviteClaim(invite.InviteID, vaultID, subjectDeviceIDBytes)
		if err != nil {
			return nil, apierror.BadRequest("sign_bytes_error", err.Error())
		}
		if err := crypto.VerifySignature(event.SubjectPubkeySign, claimSignBytes, event.ClaimSig); err != nil {
			return nil, apierror.BadRequest("invalid_claim_sig", "claim signature verification failed")
		}
	}

	actorDeviceIDBytes, err := crypto.DeviceIDToBytes(string(event.ActorDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	inviteIDBytes := event.InviteID.Bytes()
	if isGenesis {
		inviteIDBytes = make([]byte, 16)
	}
	claimSig := []byte(event.ClaimSig)
	if isGenesis {
		claimSig = make([]byte, 64)
	}

	signBytes, err := cbe.SignBytesMemberAdd(
		event.MemberEventID.Bytes(),
		vaultID,
		memberSeq,
		event.PrevHash,
		actorDeviceIDBytes,
		subjectDeviceIDBytes,
		inviteIDBytes,
		claimSig,
		event.SubjectBundleSig,
		event.SubjectPubkeySign,
		event.SubjectPubkeyBox,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	var signerPubkey []byte
	if isGenesis {
		signerPubkey = event.SubjectPubkeySign
	} else {
		actor, err := v.vaults.GetMember(ctx, vaultID, string(event.ActorDeviceID))
		if err != nil {
			return nil, apierror.InternalError()
		}
		if actor == nil || !actor.IsMember {
			return nil, apierror.MembershipRequired()
		}
		signerPubkey = actor.DevicePubkeySign
	}

	if err := crypto.VerifySignature(signerPubkey, signBytes, event.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	memberHash := crypto.SHA256Hash(signBytes)

	return &storage.MemberEventRow{
		MemberEventID:     event.MemberEventID.Bytes(),
		VaultID:           vaultID,
		MemberSeq:         memberSeq,
		PrevHash:          event.PrevHash,
		ActorDeviceID:     string(event.ActorDeviceID),
		SubjectDeviceID:   string(event.SubjectDeviceID),
		MsgType:           "member_add",
		SubjectPubkeySign: event.SubjectPubkeySign,
		SubjectPubkeyBox:  event.SubjectPubkeyBox,
		SubjectBundleSig:  event.SubjectBundleSig,
		InviteID:          event.InviteID.Bytes(),
		ClaimSig:          event.ClaimSig,
		Signature:         event.Signature,
		MemberHash:        memberHash,
		CreatedAt:         event.CreatedAt,
	}, nil
}

func (v *MembershipValidator) ValidateMemberRemove(ctx context.Context, event *models.MemberEvent) (*storage.MemberEventRow, *apierror.APIError) {
	if event.MsgType != "member_remove" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected member_remove")
	}

	if len(event.PrevHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}
	if len(event.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}

	if err := event.ActorDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	if err := event.SubjectDeviceID.Validate(); err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	vaultID := event.VaultID.Bytes()
	vault, err := v.vaults.Get(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if vault == nil {
		return nil, apierror.NotFound("vault")
	}

	if string(event.ActorDeviceID) != vault.OwnerDeviceID {
		return nil, apierror.OwnerRequired()
	}

	head, err := v.vaults.GetMembershipHead(ctx, vaultID)
	if err != nil {
		return nil, apierror.InternalError()
	}
	if head == nil {
		return nil, apierror.BadRequest("missing_membership_head", "vault membership head is missing")
	}

	memberSeq := uint64(event.MemberSeq)
	if memberSeq != head.MemberSeq+1 {
		return nil, apierror.MembershipChainBroken()
	}
	if !bytes.Equal(event.PrevHash, head.MemberHeadHash) {
		return nil, apierror.MembershipChainBroken()
	}

	isMember, err := v.vaults.IsMember(ctx, vaultID, string(event.SubjectDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if !isMember {
		return nil, apierror.BadRequest("subject_not_member", "subject_device_id is not a current member")
	}

	actorDeviceIDBytes, err := crypto.DeviceIDToBytes(string(event.ActorDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}
	subjectDeviceIDBytes, err := crypto.DeviceIDToBytes(string(event.SubjectDeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesMemberRemove(
		event.MemberEventID.Bytes(),
		vaultID,
		memberSeq,
		event.PrevHash,
		actorDeviceIDBytes,
		subjectDeviceIDBytes,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	actor, err := v.vaults.GetMember(ctx, vaultID, string(event.ActorDeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if actor == nil || !actor.IsMember {
		return nil, apierror.MembershipRequired()
	}

	if err := crypto.VerifySignature(actor.DevicePubkeySign, signBytes, event.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	memberHash := crypto.SHA256Hash(signBytes)

	return &storage.MemberEventRow{
		MemberEventID:   event.MemberEventID.Bytes(),
		VaultID:         vaultID,
		MemberSeq:       memberSeq,
		PrevHash:        event.PrevHash,
		ActorDeviceID:   string(event.ActorDeviceID),
		SubjectDeviceID: string(event.SubjectDeviceID),
		MsgType:         "member_remove",
		Signature:       event.Signature,
		MemberHash:      memberHash,
		CreatedAt:       event.CreatedAt,
	}, nil
}
