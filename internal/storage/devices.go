package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
	"forgor-server/internal/models"
)

type DeviceRow struct {
	DeviceID        string
	DevicePubkeySign []byte
	DevicePubkeyBox  []byte
	DeviceBundleSig  []byte
	CreatedAt       string
}

type DevicesRepository struct {
	db *db.DB
}

func NewDevicesRepository(database *db.DB) *DevicesRepository {
	return &DevicesRepository{db: database}
}

func (r *DevicesRepository) Get(ctx context.Context, deviceID string) (*DeviceRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT device_id, device_pubkey_sign, device_pubkey_box, device_bundle_sig, created_at
		FROM devices WHERE device_id = ?
	`, deviceID)

	var d DeviceRow
	err := row.Scan(&d.DeviceID, &d.DevicePubkeySign, &d.DevicePubkeyBox, &d.DeviceBundleSig, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DevicesRepository) Create(ctx context.Context, bundle *models.DeviceBundle) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO devices (device_id, device_pubkey_sign, device_pubkey_box, device_bundle_sig, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, string(bundle.DeviceID), []byte(bundle.DevicePubkeySign), []byte(bundle.DevicePubkeyBox),
		[]byte(bundle.DeviceBundleSig), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (r *DevicesRepository) Exists(ctx context.Context, deviceID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM devices WHERE device_id = ?
	`, deviceID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
