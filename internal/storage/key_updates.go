package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
)

type KeyUpdateRow struct {
	KeyUpdateID       []byte
	VaultID           []byte
	MemberSeq         uint64
	MemberHeadHash    []byte
	TargetDeviceID    string
	KeyEpoch          uint64
	Nonce             []byte
	WrappedPayload    []byte
	CreatedByDeviceID string
	Signature         []byte
	CreatedAt         string
}

type KeyUpdateAckRow struct {
	VaultID        []byte
	KeyEpoch       uint64
	DeviceID       string
	MemberSeq      uint64
	MemberHeadHash []byte
	Signature      []byte
	CreatedAt      string
}

type KeyUpdatesRepository struct {
	db *db.DB
}

func NewKeyUpdatesRepository(database *db.DB) *KeyUpdatesRepository {
	return &KeyUpdatesRepository{db: database}
}

func (r *KeyUpdatesRepository) Create(ctx context.Context, ku *KeyUpdateRow) error {
	if ku.CreatedAt == "" {
		ku.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_updates (key_update_id, vault_id, member_seq, member_head_hash, target_device_id, key_epoch, nonce, wrapped_payload, created_by_device_id, signature, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ku.KeyUpdateID, ku.VaultID, ku.MemberSeq, ku.MemberHeadHash, ku.TargetDeviceID, ku.KeyEpoch, ku.Nonce, ku.WrappedPayload, ku.CreatedByDeviceID, ku.Signature, ku.CreatedAt)
	return err
}

func (r *KeyUpdatesRepository) Get(ctx context.Context, keyUpdateID []byte) (*KeyUpdateRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT key_update_id, vault_id, member_seq, member_head_hash, target_device_id, key_epoch, nonce, wrapped_payload, created_by_device_id, signature, created_at
		FROM key_updates WHERE key_update_id = ?
	`, keyUpdateID)

	var ku KeyUpdateRow
	err := row.Scan(&ku.KeyUpdateID, &ku.VaultID, &ku.MemberSeq, &ku.MemberHeadHash, &ku.TargetDeviceID, &ku.KeyEpoch, &ku.Nonce, &ku.WrappedPayload, &ku.CreatedByDeviceID, &ku.Signature, &ku.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ku, nil
}

func (r *KeyUpdatesRepository) ListByTargetDevice(ctx context.Context, targetDeviceID string) ([]*KeyUpdateRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT key_update_id, vault_id, member_seq, member_head_hash, target_device_id, key_epoch, nonce, wrapped_payload, created_by_device_id, signature, created_at
		FROM key_updates WHERE target_device_id = ?
		ORDER BY created_at DESC
	`, targetDeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var updates []*KeyUpdateRow
	for rows.Next() {
		var ku KeyUpdateRow
		if err := rows.Scan(&ku.KeyUpdateID, &ku.VaultID, &ku.MemberSeq, &ku.MemberHeadHash, &ku.TargetDeviceID, &ku.KeyEpoch, &ku.Nonce, &ku.WrappedPayload, &ku.CreatedByDeviceID, &ku.Signature, &ku.CreatedAt); err != nil {
			return nil, err
		}
		updates = append(updates, &ku)
	}
	return updates, rows.Err()
}

func (r *KeyUpdatesRepository) CheckExists(ctx context.Context, vaultID []byte, keyEpoch uint64, targetDeviceID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM key_updates WHERE vault_id = ? AND key_epoch = ? AND target_device_id = ?
	`, vaultID, keyEpoch, targetDeviceID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *KeyUpdatesRepository) CreateAck(ctx context.Context, ack *KeyUpdateAckRow) error {
	if ack.CreatedAt == "" {
		ack.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_update_acks (vault_id, key_epoch, device_id, member_seq, member_head_hash, signature, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vault_id, key_epoch, device_id) DO NOTHING
	`, ack.VaultID, ack.KeyEpoch, ack.DeviceID, ack.MemberSeq, ack.MemberHeadHash, ack.Signature, ack.CreatedAt)
	return err
}

func (r *KeyUpdatesRepository) GetAck(ctx context.Context, vaultID []byte, keyEpoch uint64, deviceID string) (*KeyUpdateAckRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT vault_id, key_epoch, device_id, member_seq, member_head_hash, signature, created_at
		FROM key_update_acks WHERE vault_id = ? AND key_epoch = ? AND device_id = ?
	`, vaultID, keyEpoch, deviceID)

	var ack KeyUpdateAckRow
	err := row.Scan(&ack.VaultID, &ack.KeyEpoch, &ack.DeviceID, &ack.MemberSeq, &ack.MemberHeadHash, &ack.Signature, &ack.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ack, nil
}
