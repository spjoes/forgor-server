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

type EventsValidator struct {
	vaults *storage.VaultsRepository
	events *storage.EventsRepository
}

func NewEventsValidator(vaults *storage.VaultsRepository, events *storage.EventsRepository) *EventsValidator {
	return &EventsValidator{
		vaults: vaults,
		events: events,
	}
}

func (v *EventsValidator) ValidateEvent(ctx context.Context, event *models.Event) (*storage.EventRow, *apierror.APIError) {
	if event.MsgType != "event" {
		return nil, apierror.BadRequest("invalid_msg_type", "expected 'event'")
	}

	if len(event.PrevHash) != models.HashLength {
		return nil, apierror.InvalidHash()
	}
	if len(event.Nonce) != models.NonceLength {
		return nil, apierror.InvalidNonce()
	}
	if len(event.Signature) != models.SignatureLength {
		return nil, apierror.InvalidSignature()
	}
	if len(event.Ciphertext) > models.MaxEventCiphertext {
		return nil, apierror.PayloadTooLarge("event ciphertext exceeds maximum size")
	}

	if err := event.DeviceID.Validate(); err != nil {
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

	member, err := v.vaults.GetMember(ctx, vaultID, string(event.DeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}
	if member == nil || !member.IsMember {
		return nil, apierror.MembershipRequired()
	}

	counter := uint64(event.Counter)
	head, err := v.events.GetEventHead(ctx, vaultID, string(event.DeviceID))
	if err != nil {
		return nil, apierror.InternalError()
	}

	if head == nil {
		if counter != 1 {
			return nil, apierror.EventChainBroken()
		}
		if !bytes.Equal(event.PrevHash, models.Zero32) {
			return nil, apierror.EventChainBroken()
		}
	} else {
		if counter != head.LastCounter+1 {
			return nil, apierror.EventChainBroken()
		}
		if !bytes.Equal(event.PrevHash, head.LastHash) {
			return nil, apierror.EventChainBroken()
		}
	}

	exists, err := v.events.CheckEventIDExists(ctx, vaultID, string(event.DeviceID), event.EventID.Bytes())
	if err != nil {
		return nil, apierror.InternalError()
	}
	if exists {
		return nil, apierror.Conflict("event_id already exists")
	}

	deviceIDBytes, err := crypto.DeviceIDToBytes(string(event.DeviceID))
	if err != nil {
		return nil, apierror.InvalidDeviceID()
	}

	signBytes, err := cbe.SignBytesEvent(
		event.EventID.Bytes(),
		vaultID,
		deviceIDBytes,
		counter,
		uint64(event.Lamport),
		uint64(event.KeyEpoch),
		event.PrevHash,
		event.Nonce,
		event.Ciphertext,
	)
	if err != nil {
		return nil, apierror.BadRequest("sign_bytes_error", err.Error())
	}

	if err := crypto.VerifySignature(member.DevicePubkeySign, signBytes, event.Signature); err != nil {
		return nil, apierror.InvalidSignature()
	}

	eventHash := crypto.SHA256Hash(signBytes)

	return &storage.EventRow{
		EventID:    event.EventID.Bytes(),
		EventHash:  eventHash,
		VaultID:    vaultID,
		DeviceID:   string(event.DeviceID),
		Counter:    counter,
		Lamport:    uint64(event.Lamport),
		KeyEpoch:   uint64(event.KeyEpoch),
		PrevHash:   event.PrevHash,
		Nonce:      event.Nonce,
		Ciphertext: event.Ciphertext,
		Signature:  event.Signature,
		CreatedAt:  event.CreatedAt,
	}, nil
}
