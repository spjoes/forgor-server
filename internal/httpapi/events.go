package httpapi

import (
	"bytes"
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/models"
	"forgor-server/internal/storage"
)

func (s *Server) handleEventCreate(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var event models.Event
	if apiErr := parseJSON(r, &event); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(vaultID, event.VaultID.Bytes()) {
		apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.eventsValidator.ValidateEvent(ctx, &event)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	seq, err := s.events.Create(ctx, row)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	head := &storage.EventHead{
		VaultID:     vaultID,
		DeviceID:    row.DeviceID,
		LastCounter: row.Counter,
		LastHash:    row.EventHash,
	}
	if err := s.events.UpsertEventHead(ctx, head); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := models.EventResponse{
		Seq: models.Uint64String(seq),
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	sinceSeqStr := getQueryParam(r, "since_seq")
	var sinceSeq uint64
	if sinceSeqStr != "" {
		sinceSeq, err = parseUint64(sinceSeqStr)
		if err != nil {
			apierror.BadRequest("invalid_since_seq", "since_seq must be a valid integer").WriteJSON(w)
			return
		}
	}

	events, err := s.events.ListSince(r.Context(), vaultID, sinceSeq)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := make([]models.Event, 0, len(events))
	for _, e := range events {
		response = append(response, models.Event{
			MsgType:    "event",
			EventID:    bytesToUUID(e.EventID),
			VaultID:    bytesToUUID(e.VaultID),
			DeviceID:   models.DeviceID(e.DeviceID),
			Counter:    models.Uint64String(e.Counter),
			Lamport:    models.Uint64String(e.Lamport),
			KeyEpoch:   models.Uint64String(e.KeyEpoch),
			PrevHash:   e.PrevHash,
			Nonce:      e.Nonce,
			Ciphertext: e.Ciphertext,
			Signature:  e.Signature,
			Seq:        models.Uint64String(e.Seq),
			CreatedAt:  e.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, response)
}
