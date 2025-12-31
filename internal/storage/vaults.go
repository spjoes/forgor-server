package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"forgor-server/internal/db"
)

type VaultRow struct {
	VaultID       []byte
	OwnerDeviceID string
	CreatedAt     string
	UpdatedAt     string
}

type VaultMembershipHead struct {
	VaultID        []byte
	MemberSeq      uint64
	MemberHeadHash []byte
}

type VaultMemberRow struct {
	VaultID          []byte
	DeviceID         string
	DevicePubkeySign []byte
	DevicePubkeyBox  []byte
	SubjectBundleSig []byte
	IsMember         bool
	KeyEpoch         uint64
}

type VaultsRepository struct {
	db *db.DB
}

func NewVaultsRepository(database *db.DB) *VaultsRepository {
	return &VaultsRepository{db: database}
}

func (r *VaultsRepository) Get(ctx context.Context, vaultID []byte) (*VaultRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT vault_id, owner_device_id, created_at, updated_at
		FROM vaults WHERE vault_id = ?
	`, vaultID)

	var v VaultRow
	err := row.Scan(&v.VaultID, &v.OwnerDeviceID, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *VaultsRepository) Create(ctx context.Context, vaultID []byte, ownerDeviceID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vaults (vault_id, owner_device_id, created_at, updated_at)
		VALUES (?, ?, ?, ?)
	`, vaultID, ownerDeviceID, now, now)
	return err
}

func (r *VaultsRepository) GetMembershipHead(ctx context.Context, vaultID []byte) (*VaultMembershipHead, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT vault_id, member_seq, member_head_hash
		FROM vault_membership_heads WHERE vault_id = ?
	`, vaultID)

	var h VaultMembershipHead
	err := row.Scan(&h.VaultID, &h.MemberSeq, &h.MemberHeadHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (r *VaultsRepository) UpsertMembershipHead(ctx context.Context, vaultID []byte, memberSeq uint64, memberHeadHash []byte) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vault_membership_heads (vault_id, member_seq, member_head_hash)
		VALUES (?, ?, ?)
		ON CONFLICT(vault_id) DO UPDATE SET member_seq = excluded.member_seq, member_head_hash = excluded.member_head_hash
	`, vaultID, memberSeq, memberHeadHash)
	return err
}

func (r *VaultsRepository) GetMember(ctx context.Context, vaultID []byte, deviceID string) (*VaultMemberRow, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT vault_id, device_id, device_pubkey_sign, device_pubkey_box, subject_bundle_sig, is_member, key_epoch
		FROM vault_members WHERE vault_id = ? AND device_id = ?
	`, vaultID, deviceID)

	var m VaultMemberRow
	err := row.Scan(&m.VaultID, &m.DeviceID, &m.DevicePubkeySign, &m.DevicePubkeyBox, &m.SubjectBundleSig, &m.IsMember, &m.KeyEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *VaultsRepository) UpsertMember(ctx context.Context, m *VaultMemberRow) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vault_members (vault_id, device_id, device_pubkey_sign, device_pubkey_box, subject_bundle_sig, is_member, key_epoch)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vault_id, device_id) DO UPDATE SET 
			device_pubkey_sign = excluded.device_pubkey_sign,
			device_pubkey_box = excluded.device_pubkey_box,
			subject_bundle_sig = excluded.subject_bundle_sig,
			is_member = excluded.is_member,
			key_epoch = excluded.key_epoch
	`, m.VaultID, m.DeviceID, m.DevicePubkeySign, m.DevicePubkeyBox, m.SubjectBundleSig, m.IsMember, m.KeyEpoch)
	return err
}

func (r *VaultsRepository) SetMemberRemoved(ctx context.Context, vaultID []byte, deviceID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE vault_members SET is_member = 0 WHERE vault_id = ? AND device_id = ?
	`, vaultID, deviceID)
	return err
}

func (r *VaultsRepository) UpdateMemberKeyEpoch(ctx context.Context, vaultID []byte, deviceID string, keyEpoch uint64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE vault_members SET key_epoch = ? WHERE vault_id = ? AND device_id = ?
	`, keyEpoch, vaultID, deviceID)
	return err
}

func (r *VaultsRepository) ListMembers(ctx context.Context, vaultID []byte) ([]*VaultMemberRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT vault_id, device_id, device_pubkey_sign, device_pubkey_box, subject_bundle_sig, is_member, key_epoch
		FROM vault_members WHERE vault_id = ? AND is_member = 1
	`, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*VaultMemberRow
	for rows.Next() {
		var m VaultMemberRow
		if err := rows.Scan(&m.VaultID, &m.DeviceID, &m.DevicePubkeySign, &m.DevicePubkeyBox, &m.SubjectBundleSig, &m.IsMember, &m.KeyEpoch); err != nil {
			return nil, err
		}
		members = append(members, &m)
	}
	return members, rows.Err()
}

func (r *VaultsRepository) IsMember(ctx context.Context, vaultID []byte, deviceID string) (bool, error) {
	var isMember bool
	err := r.db.QueryRowContext(ctx, `
		SELECT is_member FROM vault_members WHERE vault_id = ? AND device_id = ?
	`, vaultID, deviceID).Scan(&isMember)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return isMember, nil
}
