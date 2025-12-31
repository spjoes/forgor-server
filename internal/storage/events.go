package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
)

type EventRow struct {
	Seq        uint64
	EventID    []byte
	EventHash  []byte
	VaultID    []byte
	DeviceID   string
	Counter    uint64
	Lamport    uint64
	KeyEpoch   uint64
	PrevHash   []byte
	Nonce      []byte
	Ciphertext []byte
	Signature  []byte
	CreatedAt  string
}

type EventHead struct {
	VaultID     []byte
	DeviceID    string
	LastCounter uint64
	LastHash    []byte
}

type EventsRepository struct {
	db *db.DB
}

func NewEventsRepository(database *db.DB) *EventsRepository {
	return &EventsRepository{db: database}
}

func (r *EventsRepository) Create(ctx context.Context, e *EventRow) (uint64, error) {
	if e.CreatedAt == "" {
		e.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO events (event_id, event_hash, vault_id, device_id, counter, lamport, key_epoch, prev_hash, nonce, ciphertext, signature, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.EventID, e.EventHash, e.VaultID, e.DeviceID, e.Counter, e.Lamport, e.KeyEpoch, e.PrevHash, e.Nonce, e.Ciphertext, e.Signature, e.CreatedAt)
	if err != nil {
		return 0, err
	}

	seq, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return uint64(seq), nil
}

func (r *EventsRepository) ListSince(ctx context.Context, vaultID []byte, sinceSeq uint64) ([]*EventRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT seq, event_id, event_hash, vault_id, device_id, counter, lamport, key_epoch, prev_hash, nonce, ciphertext, signature, created_at
		FROM events
		WHERE vault_id = ? AND seq > ?
		ORDER BY seq ASC
	`, vaultID, sinceSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.Seq, &e.EventID, &e.EventHash, &e.VaultID, &e.DeviceID, &e.Counter, &e.Lamport, &e.KeyEpoch, &e.PrevHash, &e.Nonce, &e.Ciphertext, &e.Signature, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

func (r *EventsRepository) GetEventHead(ctx context.Context, vaultID []byte, deviceID string) (*EventHead, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT vault_id, device_id, last_counter, last_hash
		FROM event_heads WHERE vault_id = ? AND device_id = ?
	`, vaultID, deviceID)

	var h EventHead
	err := row.Scan(&h.VaultID, &h.DeviceID, &h.LastCounter, &h.LastHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (r *EventsRepository) UpsertEventHead(ctx context.Context, h *EventHead) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO event_heads (vault_id, device_id, last_counter, last_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(vault_id, device_id) DO UPDATE SET last_counter = excluded.last_counter, last_hash = excluded.last_hash
	`, h.VaultID, h.DeviceID, h.LastCounter, h.LastHash)
	return err
}

func (r *EventsRepository) CheckEventIDExists(ctx context.Context, vaultID []byte, deviceID string, eventID []byte) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM events WHERE vault_id = ? AND device_id = ? AND event_id = ?
	`, vaultID, deviceID, eventID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
