package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
)

type InviteRow struct {
	InviteID              []byte
	VaultID               []byte
	TargetDeviceID        string
	TargetDevicePubkeySign []byte
	TargetDevicePubkeyBox  []byte
	TargetDeviceBundleSig  []byte
	Nonce                 []byte
	WrappedPayload        []byte
	CreatedByDeviceID     string
	SingleUse             bool
	Used                  bool
	Signature             []byte
	CreatedAt             string
}

type InviteClaimRow struct {
	InviteID  []byte
	VaultID   []byte
	DeviceID  string
	ClaimSig  []byte
	CreatedAt string
}

type InvitesRepository struct {
	db *db.DB
}

func NewInvitesRepository(database *db.DB) *InvitesRepository {
	return &InvitesRepository{db: database}
}

func (r *InvitesRepository) Create(ctx context.Context, inv *InviteRow) error {
	if inv.CreatedAt == "" {
		inv.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO invites (
			invite_id, vault_id, target_device_id, target_device_pubkey_sign, target_device_pubkey_box,
			target_device_bundle_sig, nonce, wrapped_payload, created_by_device_id, single_use, used, signature, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, inv.InviteID, inv.VaultID, inv.TargetDeviceID, inv.TargetDevicePubkeySign, inv.TargetDevicePubkeyBox,
		inv.TargetDeviceBundleSig, inv.Nonce, inv.WrappedPayload, inv.CreatedByDeviceID, inv.SingleUse, inv.Used, inv.Signature, inv.CreatedAt)
	return err
}

func (r *InvitesRepository) Get(ctx context.Context, inviteID []byte) (*InviteRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT invite_id, vault_id, target_device_id, target_device_pubkey_sign, target_device_pubkey_box,
			   target_device_bundle_sig, nonce, wrapped_payload, created_by_device_id, single_use, used, signature, created_at
		FROM invites WHERE invite_id = ?
	`, inviteID)

	var inv InviteRow
	err := row.Scan(&inv.InviteID, &inv.VaultID, &inv.TargetDeviceID, &inv.TargetDevicePubkeySign, &inv.TargetDevicePubkeyBox,
		&inv.TargetDeviceBundleSig, &inv.Nonce, &inv.WrappedPayload, &inv.CreatedByDeviceID, &inv.SingleUse, &inv.Used, &inv.Signature, &inv.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

func (r *InvitesRepository) ListByTargetDevice(ctx context.Context, targetDeviceID string) ([]*InviteRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT invite_id, vault_id, target_device_id, target_device_pubkey_sign, target_device_pubkey_box,
			   target_device_bundle_sig, nonce, wrapped_payload, created_by_device_id, single_use, used, signature, created_at
		FROM invites WHERE target_device_id = ?
		ORDER BY created_at DESC
	`, targetDeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []*InviteRow
	for rows.Next() {
		var inv InviteRow
		if err := rows.Scan(&inv.InviteID, &inv.VaultID, &inv.TargetDeviceID, &inv.TargetDevicePubkeySign, &inv.TargetDevicePubkeyBox,
			&inv.TargetDeviceBundleSig, &inv.Nonce, &inv.WrappedPayload, &inv.CreatedByDeviceID, &inv.SingleUse, &inv.Used, &inv.Signature, &inv.CreatedAt); err != nil {
			return nil, err
		}
		invites = append(invites, &inv)
	}
	return invites, rows.Err()
}

func (r *InvitesRepository) MarkUsed(ctx context.Context, inviteID []byte) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE invites SET used = 1 WHERE invite_id = ?
	`, inviteID)
	return err
}

func (r *InvitesRepository) CreateClaim(ctx context.Context, claim *InviteClaimRow) error {
	if claim.CreatedAt == "" {
		claim.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO invite_claims (invite_id, vault_id, device_id, claim_sig, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(invite_id, device_id) DO NOTHING
	`, claim.InviteID, claim.VaultID, claim.DeviceID, claim.ClaimSig, claim.CreatedAt)
	return err
}

func (r *InvitesRepository) GetClaim(ctx context.Context, inviteID []byte, deviceID string) (*InviteClaimRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT invite_id, vault_id, device_id, claim_sig, created_at
		FROM invite_claims WHERE invite_id = ? AND device_id = ?
	`, inviteID, deviceID)

	var claim InviteClaimRow
	err := row.Scan(&claim.InviteID, &claim.VaultID, &claim.DeviceID, &claim.ClaimSig, &claim.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &claim, nil
}

func (r *InvitesRepository) ListClaimsByCreator(ctx context.Context, createdByDeviceID string) ([]*InviteClaimRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ic.invite_id, ic.vault_id, ic.device_id, ic.claim_sig, ic.created_at
		FROM invite_claims ic
		INNER JOIN invites i ON ic.invite_id = i.invite_id
		WHERE i.created_by_device_id = ?
		ORDER BY ic.created_at DESC
	`, createdByDeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []*InviteClaimRow
	for rows.Next() {
		var claim InviteClaimRow
		if err := rows.Scan(&claim.InviteID, &claim.VaultID, &claim.DeviceID, &claim.ClaimSig, &claim.CreatedAt); err != nil {
			return nil, err
		}
		claims = append(claims, &claim)
	}
	return claims, rows.Err()
}

func (r *InvitesRepository) CheckNonceUsed(ctx context.Context, nonceType string, vaultID []byte, deviceID string, nonce []byte) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM used_nonces WHERE nonce_type = ? AND vault_id = ? AND device_id = ? AND nonce = ?
	`, nonceType, vaultID, deviceID, nonce).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *InvitesRepository) RecordNonceUsed(ctx context.Context, nonceType string, vaultID []byte, deviceID string, nonce []byte) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO used_nonces (nonce_type, vault_id, device_id, nonce, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`, nonceType, vaultID, deviceID, nonce, time.Now().UTC().Format(time.RFC3339))
	return err
}
