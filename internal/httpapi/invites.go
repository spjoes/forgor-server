package httpapi

import (
	"bytes"
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/models"
)

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var invite models.Invite
	if apiErr := parseJSON(r, &invite); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(vaultID, invite.VaultID.Bytes()) {
		apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.invitesValidator.ValidateInvite(ctx, &invite)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if err := s.invites.RecordNonceUsed(ctx, "invite", vaultID, string(invite.CreatedByDeviceID), invite.Nonce); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if err := s.invites.Create(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, invite)
}

func (s *Server) handleInvitesList(w http.ResponseWriter, r *http.Request) {
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

	invites, err := s.invites.ListByTargetDevice(r.Context(), deviceID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := make([]models.Invite, 0, len(invites))
	for _, inv := range invites {
		response = append(response, models.Invite{
			MsgType:               "invite",
			InviteID:              bytesToUUID(inv.InviteID),
			VaultID:               bytesToUUID(inv.VaultID),
			TargetDeviceID:        models.DeviceID(inv.TargetDeviceID),
			TargetDevicePubkeySign: inv.TargetDevicePubkeySign,
			TargetDevicePubkeyBox:  inv.TargetDevicePubkeyBox,
			TargetDeviceBundleSig:  inv.TargetDeviceBundleSig,
			Nonce:                 inv.Nonce,
			WrappedPayload:        inv.WrappedPayload,
			CreatedByDeviceID:     models.DeviceID(inv.CreatedByDeviceID),
			SingleUse:             inv.SingleUse,
			Signature:             inv.Signature,
			CreatedAt:             inv.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleInviteClaim(w http.ResponseWriter, r *http.Request) {
	inviteIDStr := getPathParam(r, "invite_id")
	inviteUUID, err := parseUUID(inviteIDStr)
	if err != nil {
		apierror.InvalidUUID("invite_id").WriteJSON(w)
		return
	}

	var claim models.InviteClaim
	if apiErr := parseJSON(r, &claim); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(inviteUUID[:], claim.InviteID.Bytes()) {
		apierror.BadRequest("invite_id_mismatch", "invite_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.invitesValidator.ValidateInviteClaim(ctx, &claim)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if err := s.invites.CreateClaim(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, claim)
}

func (s *Server) handleInviteClaimsList(w http.ResponseWriter, r *http.Request) {
	deviceID := getQueryParam(r, "created_by_device_id")
	if deviceID == "" {
		apierror.BadRequest("missing_device_id", "created_by_device_id query parameter is required").WriteJSON(w)
		return
	}

	did := models.DeviceID(deviceID)
	if err := did.Validate(); err != nil {
		apierror.InvalidDeviceID().WriteJSON(w)
		return
	}

	claims, err := s.invites.ListClaimsByCreator(r.Context(), deviceID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := make([]models.InviteClaim, 0, len(claims))
	for _, c := range claims {
		response = append(response, models.InviteClaim{
			MsgType:   "invite_claim",
			InviteID:  bytesToUUID(c.InviteID),
			VaultID:   bytesToUUID(c.VaultID),
			DeviceID:  models.DeviceID(c.DeviceID),
			Signature: c.ClaimSig,
			CreatedAt: c.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

func bytesToUUID(b []byte) models.UUID {
	var u [16]byte
	copy(u[:], b)
	return models.UUID(u)
}
