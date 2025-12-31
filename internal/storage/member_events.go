package storage

import (
	"context"
	"time"

	"forgor-server/internal/db"
)

type MemberEventRow struct {
	MemberEventID     []byte
	VaultID           []byte
	MemberSeq         uint64
	PrevHash          []byte
	ActorDeviceID     string
	SubjectDeviceID   string
	MsgType           string
	SubjectPubkeySign []byte
	SubjectPubkeyBox  []byte
	SubjectBundleSig  []byte
	InviteID          []byte
	ClaimSig          []byte
	Signature         []byte
	MemberHash        []byte
	CreatedAt         string
}

type MemberEventsRepository struct {
	db *db.DB
}

func NewMemberEventsRepository(database *db.DB) *MemberEventsRepository {
	return &MemberEventsRepository{db: database}
}

func (r *MemberEventsRepository) Create(ctx context.Context, e *MemberEventRow) error {
	if e.CreatedAt == "" {
		e.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO member_events (
			member_event_id, vault_id, member_seq, prev_hash, actor_device_id, subject_device_id,
			msg_type, subject_pubkey_sign, subject_pubkey_box, subject_bundle_sig, invite_id, claim_sig,
			signature, member_hash, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.MemberEventID, e.VaultID, e.MemberSeq, e.PrevHash, e.ActorDeviceID, e.SubjectDeviceID,
		e.MsgType, e.SubjectPubkeySign, e.SubjectPubkeyBox, e.SubjectBundleSig, e.InviteID, e.ClaimSig,
		e.Signature, e.MemberHash, e.CreatedAt)
	return err
}

func (r *MemberEventsRepository) ListSince(ctx context.Context, vaultID []byte, sinceSeq uint64) ([]*MemberEventRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT member_event_id, vault_id, member_seq, prev_hash, actor_device_id, subject_device_id,
			   msg_type, subject_pubkey_sign, subject_pubkey_box, subject_bundle_sig, invite_id, claim_sig,
			   signature, member_hash, created_at
		FROM member_events
		WHERE vault_id = ? AND member_seq > ?
		ORDER BY member_seq ASC
	`, vaultID, sinceSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*MemberEventRow
	for rows.Next() {
		var e MemberEventRow
		if err := rows.Scan(&e.MemberEventID, &e.VaultID, &e.MemberSeq, &e.PrevHash, &e.ActorDeviceID, &e.SubjectDeviceID,
			&e.MsgType, &e.SubjectPubkeySign, &e.SubjectPubkeyBox, &e.SubjectBundleSig, &e.InviteID, &e.ClaimSig,
			&e.Signature, &e.MemberHash, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

func (r *MemberEventsRepository) GetByID(ctx context.Context, memberEventID []byte) (*MemberEventRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT member_event_id, vault_id, member_seq, prev_hash, actor_device_id, subject_device_id,
			   msg_type, subject_pubkey_sign, subject_pubkey_box, subject_bundle_sig, invite_id, claim_sig,
			   signature, member_hash, created_at
		FROM member_events WHERE member_event_id = ?
	`, memberEventID)

	var e MemberEventRow
	err := row.Scan(&e.MemberEventID, &e.VaultID, &e.MemberSeq, &e.PrevHash, &e.ActorDeviceID, &e.SubjectDeviceID,
		&e.MsgType, &e.SubjectPubkeySign, &e.SubjectPubkeyBox, &e.SubjectBundleSig, &e.InviteID, &e.ClaimSig,
		&e.Signature, &e.MemberHash, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}
