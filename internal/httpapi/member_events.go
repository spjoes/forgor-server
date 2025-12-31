package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/models"
	"forgor-server/internal/storage"
)

func (s *Server) handleMemberEventCreate(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		apierror.BadRequest("invalid_json", "failed to parse JSON").WriteJSON(w)
		return
	}

	var msgTypeCheck struct {
		MsgType string `json:"msg_type"`
	}
	if err := json.Unmarshal(raw, &msgTypeCheck); err != nil {
		apierror.BadRequest("invalid_json", "failed to parse msg_type").WriteJSON(w)
		return
	}

	ctx := r.Context()
	var row *storage.MemberEventRow
	var event models.MemberEvent

	switch msgTypeCheck.MsgType {
	case "member_add":
		if err := json.Unmarshal(raw, &event); err != nil {
			apierror.BadRequest("invalid_json", "failed to parse member_add").WriteJSON(w)
			return
		}

		if !bytes.Equal(vaultID, event.VaultID.Bytes()) {
			apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
			return
		}

		var apiErr *apierror.APIError
		row, apiErr = s.membershipValidator.ValidateMemberAdd(ctx, &event)
		if apiErr != nil {
			apiErr.WriteJSON(w)
			return
		}

	case "member_remove":
		if err := json.Unmarshal(raw, &event); err != nil {
			apierror.BadRequest("invalid_json", "failed to parse member_remove").WriteJSON(w)
			return
		}

		if !bytes.Equal(vaultID, event.VaultID.Bytes()) {
			apierror.BadRequest("vault_id_mismatch", "vault_id in path does not match body").WriteJSON(w)
			return
		}

		var apiErr *apierror.APIError
		row, apiErr = s.membershipValidator.ValidateMemberRemove(ctx, &event)
		if apiErr != nil {
			apiErr.WriteJSON(w)
			return
		}

	default:
		apierror.BadRequest("invalid_msg_type", "msg_type must be 'member_add' or 'member_remove'").WriteJSON(w)
		return
	}

	isGenesis := row.MemberSeq == 1

	if isGenesis {
		if err := s.vaults.Create(ctx, vaultID, row.ActorDeviceID); err != nil {
			apierror.InternalError().WriteJSON(w)
			return
		}
	}

	if err := s.memberEvents.Create(ctx, row); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if err := s.vaults.UpsertMembershipHead(ctx, vaultID, row.MemberSeq, row.MemberHash); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if msgTypeCheck.MsgType == "member_add" {
		member := &storage.VaultMemberRow{
			VaultID:          vaultID,
			DeviceID:         row.SubjectDeviceID,
			DevicePubkeySign: row.SubjectPubkeySign,
			DevicePubkeyBox:  row.SubjectPubkeyBox,
			SubjectBundleSig: row.SubjectBundleSig,
			IsMember:         true,
			KeyEpoch:         1,
		}
		if err := s.vaults.UpsertMember(ctx, member); err != nil {
			apierror.InternalError().WriteJSON(w)
			return
		}

		if !isGenesis && row.InviteID != nil {
			if err := s.invites.MarkUsed(ctx, row.InviteID); err != nil { }
		}
	} else {
		if err := s.vaults.SetMemberRemoved(ctx, vaultID, row.SubjectDeviceID); err != nil {
			apierror.InternalError().WriteJSON(w)
			return
		}
	}

	writeJSON(w, http.StatusCreated, event)
}

func (s *Server) handleMemberEventsList(w http.ResponseWriter, r *http.Request) {
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

	events, err := s.memberEvents.ListSince(r.Context(), vaultID, sinceSeq)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	response := make([]models.MemberEvent, 0, len(events))
	for _, e := range events {
		me := models.MemberEvent{
			MsgType:         e.MsgType,
			MemberEventID:   bytesToUUID(e.MemberEventID),
			VaultID:         bytesToUUID(e.VaultID),
			MemberSeq:       models.Uint64String(e.MemberSeq),
			PrevHash:        e.PrevHash,
			ActorDeviceID:   models.DeviceID(e.ActorDeviceID),
			SubjectDeviceID: models.DeviceID(e.SubjectDeviceID),
			Signature:       e.Signature,
			CreatedAt:       e.CreatedAt,
		}
		if e.MsgType == "member_add" {
			me.SubjectPubkeySign = e.SubjectPubkeySign
			me.SubjectPubkeyBox = e.SubjectPubkeyBox
			me.SubjectBundleSig = e.SubjectBundleSig
			me.InviteID = bytesToUUID(e.InviteID)
			me.ClaimSig = e.ClaimSig
		}
		response = append(response, me)
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleVaultMembersList(w http.ResponseWriter, r *http.Request) {
	vaultID, err := extractVaultID(r)
	if err != nil {
		apierror.InvalidUUID("vault_id").WriteJSON(w)
		return
	}

	ctx := r.Context()

	head, err := s.vaults.GetMembershipHead(ctx, vaultID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}
	if head == nil {
		apierror.NotFound("vault").WriteJSON(w)
		return
	}

	members, err := s.vaults.ListMembers(ctx, vaultID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	memberList := make([]models.VaultMember, 0, len(members))
	for _, m := range members {
		memberList = append(memberList, models.VaultMember{
			DeviceID:        models.DeviceID(m.DeviceID),
			DevicePubkeySign: m.DevicePubkeySign,
			DevicePubkeyBox:  m.DevicePubkeyBox,
			KeyEpoch:        models.Uint64String(m.KeyEpoch),
		})
	}

	response := models.VaultMembershipResponse{
		MemberSeq: models.Uint64String(head.MemberSeq),
		HeadHash:  head.MemberHeadHash,
		Members:   memberList,
	}

	writeJSON(w, http.StatusOK, response)
}
