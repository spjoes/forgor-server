package httpapi

import (
	"bytes"
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/models"
)

func (s *Server) handleSnapshotCreate(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var snapshot models.Snapshot
	if apiErr := parseJSON(r, &snapshot); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if !bytes.Equal(vaultID, snapshot.VaultID.Bytes()) {
		apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
		return
	}

	ctx := r.Context()

	row, apiErr := s.snapshotsValidator.ValidateSnapshot(ctx, &snapshot)
	if apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	if err := s.invites.RecordNonceUsed(ctx, "snapshot", vaultID, string(snapshot.CreatedByDeviceID), snapshot.Nonce); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if err := s.snapshots.Create(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	go func() {
		_ = s.snapshots.PruneOld(ctx, vaultID, 3)
	}()

	writeJSON(w, http.StatusCreated, snapshot)
}

func (s *Server) handleSnapshotLatest(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	snapshot, err := s.snapshots.GetLatest(r.Context(), vaultID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if snapshot == nil {
		apierror.NotFound("snapshot").WriteJSON(w)
		return
	}

	response := models.Snapshot{
		MsgType:           "snapshot",
		SnapshotID:        bytesToUUID(snapshot.SnapshotID),
		VaultID:           bytesToUUID(snapshot.VaultID),
		BaseSeq:           models.Uint64String(snapshot.BaseSeq),
		MemberSeq:         models.Uint64String(snapshot.MemberSeq),
		MemberHeadHash:    snapshot.MemberHeadHash,
		BaseCounterMap:    snapshot.BaseCounterMap,
		HeadHashMap:       snapshot.HeadHashMap,
		LamportAtSnapshot: models.Uint64String(snapshot.LamportAtSnapshot),
		KeyEpoch:          models.Uint64String(snapshot.KeyEpoch),
		Nonce:             snapshot.Nonce,
		Ciphertext:        snapshot.Ciphertext,
		Signature:         snapshot.Signature,
		CreatedByDeviceID: models.DeviceID(snapshot.CreatedByDeviceID),
		CreatedAt:         snapshot.CreatedAt,
	}

	writeJSON(w, http.StatusOK, response)
}
