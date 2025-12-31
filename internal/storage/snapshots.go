package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
)

type SnapshotRow struct {
	SnapshotID        []byte
	VaultID           []byte
	BaseSeq           uint64
	MemberSeq         uint64
	MemberHeadHash    []byte
	BaseCounterMap    []byte
	HeadHashMap       []byte
	LamportAtSnapshot uint64
	KeyEpoch          uint64
	Nonce             []byte
	Ciphertext        []byte
	Signature         []byte
	CreatedByDeviceID string
	CreatedAt         string
}

type SnapshotsRepository struct {
	db *db.DB
}

func NewSnapshotsRepository(database *db.DB) *SnapshotsRepository {
	return &SnapshotsRepository{db: database}
}

func (r *SnapshotsRepository) Create(ctx context.Context, s *SnapshotRow) error {
	if s.CreatedAt == "" {
		s.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO snapshots (snapshot_id, vault_id, base_seq, member_seq, member_head_hash, base_counter_map, head_hash_map, lamport_at_snapshot, key_epoch, nonce, ciphertext, signature, created_by_device_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, s.SnapshotID, s.VaultID, s.BaseSeq, s.MemberSeq, s.MemberHeadHash, s.BaseCounterMap, s.HeadHashMap, s.LamportAtSnapshot, s.KeyEpoch, s.Nonce, s.Ciphertext, s.Signature, s.CreatedByDeviceID, s.CreatedAt)
	return err
}

func (r *SnapshotsRepository) GetLatest(ctx context.Context, vaultID []byte) (*SnapshotRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT snapshot_id, vault_id, base_seq, member_seq, member_head_hash, base_counter_map, head_hash_map, lamport_at_snapshot, key_epoch, nonce, ciphertext, signature, created_by_device_id, created_at
		FROM snapshots
		WHERE vault_id = ?
		ORDER BY base_seq DESC
		LIMIT 1
	`, vaultID)

	var s SnapshotRow
	err := row.Scan(&s.SnapshotID, &s.VaultID, &s.BaseSeq, &s.MemberSeq, &s.MemberHeadHash, &s.BaseCounterMap, &s.HeadHashMap, &s.LamportAtSnapshot, &s.KeyEpoch, &s.Nonce, &s.Ciphertext, &s.Signature, &s.CreatedByDeviceID, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SnapshotsRepository) PruneOld(ctx context.Context, vaultID []byte, keepCount int) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM snapshots
		WHERE vault_id = ? AND snapshot_id NOT IN (
			SELECT snapshot_id FROM snapshots WHERE vault_id = ? ORDER BY base_seq DESC LIMIT ?
		)
	`, vaultID, vaultID, keepCount)
	return err
}
