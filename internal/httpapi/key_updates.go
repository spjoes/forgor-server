package httpapi

import (
	"bytes"
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/models"
)

func (s *Server) handleKeyUpdateCreate(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var ku models.KeyUpdate
	if apiErr := parseJSON(r, &ku); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(vaultID, ku.VaultID.Bytes()) {
		apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.keyUpdatesValidator.ValidateKeyUpdate(ctx, &ku)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if err := s.invites.RecordNonceUsed(ctx, "key_update", vaultID, string(ku.CreatedByDeviceID), ku.Nonce); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if err := s.keyUpdates.Create(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, ku)
}

func (s *Server) handleKeyUpdatesList(w http.ResponseWriter, r *http.Request) {
	deviceID := getQueryParam(r, "device_id")
	if deviceID == "" {
		apierror.BadRequest("missing_device_id", "device_id query parameter is required").WriteJSON(w)
		return
	}

	did := models.DeviceID(deviceID)
	if err := did.Validate(); err != nil {
		apierror.InvalidDeviceID().WriteJSON(w)
		return
	}

	updates, err := s.keyUpdates.ListByTargetDevice(r.Context(), deviceID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := make([]models.KeyUpdate, 0, len(updates))
	for _, ku := range updates {
		response = append(response, models.KeyUpdate{
			MsgType:           "key_update",
			KeyUpdateID:       bytesToUUID(ku.KeyUpdateID),
			VaultID:           bytesToUUID(ku.VaultID),
			MemberSeq:         models.Uint64String(ku.MemberSeq),
			MemberHeadHash:    ku.MemberHeadHash,
			TargetDeviceID:    models.DeviceID(ku.TargetDeviceID),
			KeyEpoch:          models.Uint64String(ku.KeyEpoch),
			Nonce:             ku.Nonce,
			WrappedPayload:    ku.WrappedPayload,
			CreatedByDeviceID: models.DeviceID(ku.CreatedByDeviceID),
			Signature:         ku.Signature,
			CreatedAt:         ku.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleKeyUpdateAck(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var ack models.KeyUpdateAck
	if apiErr := parseJSON(r, &ack); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(vaultID, ack.VaultID.Bytes()) {
		apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.keyUpdatesValidator.ValidateKeyUpdateAck(ctx, &ack)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if err := s.keyUpdates.CreateAck(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if err := s.vaults.UpdateMemberKeyEpoch(ctx, vaultID, string(ack.DeviceID), uint64(ack.KeyEpoch)); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, ack)
}
