CREATE TABLE devices (
    device_id           TEXT PRIMARY KEY,
    device_pubkey_sign  BLOB NOT NULL,
    device_pubkey_box   BLOB NOT NULL,
    device_bundle_sig   BLOB NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_devices_pubkey_sign ON devices(device_pubkey_sign);

CREATE TABLE vaults (
    vault_id           BLOB PRIMARY KEY,
    owner_device_id    TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE TABLE vault_membership_heads (
    vault_id         BLOB PRIMARY KEY,
    member_seq       INTEGER NOT NULL,
    member_head_hash BLOB NOT NULL
);

CREATE TABLE vault_members (
    vault_id            BLOB NOT NULL,
    device_id           TEXT NOT NULL,
    device_pubkey_sign  BLOB NOT NULL,
    device_pubkey_box   BLOB NOT NULL,
    subject_bundle_sig  BLOB NOT NULL,
    is_member           INTEGER NOT NULL,
    key_epoch           INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (vault_id, device_id)
);

CREATE INDEX idx_vault_members_vault ON vault_members(vault_id);

CREATE TABLE member_events (
    member_event_id     BLOB PRIMARY KEY,
    vault_id            BLOB NOT NULL,
    member_seq          INTEGER NOT NULL,
    prev_hash           BLOB NOT NULL,
    actor_device_id     TEXT NOT NULL,
    subject_device_id   TEXT NOT NULL,
    msg_type            TEXT NOT NULL,
    subject_pubkey_sign BLOB,
    subject_pubkey_box  BLOB,
    subject_bundle_sig  BLOB,
    invite_id           BLOB,
    claim_sig           BLOB,
    signature           BLOB NOT NULL,
    member_hash         BLOB NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_member_events_vault_seq ON member_events(vault_id, member_seq);
CREATE INDEX idx_member_events_vault ON member_events(vault_id);

CREATE TABLE invites (
    invite_id                 BLOB PRIMARY KEY,
    vault_id                  BLOB NOT NULL,
    target_device_id          TEXT NOT NULL,
    target_device_pubkey_sign BLOB NOT NULL,
    target_device_pubkey_box  BLOB NOT NULL,
    target_device_bundle_sig  BLOB NOT NULL,
    nonce                     BLOB NOT NULL,
    wrapped_payload           BLOB NOT NULL,
    created_by_device_id      TEXT NOT NULL,
    single_use                INTEGER NOT NULL,
    used                      INTEGER NOT NULL DEFAULT 0,
    signature                 BLOB NOT NULL,
    created_at                TEXT NOT NULL
);

CREATE INDEX idx_invites_target_device_id ON invites(target_device_id);
CREATE INDEX idx_invites_created_by_device_id ON invites(created_by_device_id);
CREATE INDEX idx_invites_vault ON invites(vault_id);

CREATE TABLE invite_claims (
    invite_id       BLOB NOT NULL,
    vault_id        BLOB NOT NULL,
    device_id       TEXT NOT NULL,
    claim_sig       BLOB NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (invite_id, device_id)
);

CREATE INDEX idx_invite_claims_invite_id ON invite_claims(invite_id);

CREATE TABLE key_updates (
    key_update_id        BLOB PRIMARY KEY,
    vault_id             BLOB NOT NULL,
    member_seq           INTEGER NOT NULL,
    member_head_hash     BLOB NOT NULL,
    target_device_id     TEXT NOT NULL,
    key_epoch            INTEGER NOT NULL,
    nonce                BLOB NOT NULL,
    wrapped_payload      BLOB NOT NULL,
    created_by_device_id TEXT NOT NULL,
    signature            BLOB NOT NULL,
    created_at           TEXT NOT NULL
);

CREATE INDEX idx_key_updates_target_device_id ON key_updates(target_device_id);
CREATE INDEX idx_key_updates_vault_epoch_device ON key_updates(vault_id, key_epoch, target_device_id);
CREATE INDEX idx_key_updates_vault ON key_updates(vault_id);

CREATE TABLE key_update_acks (
    vault_id         BLOB NOT NULL,
    key_epoch        INTEGER NOT NULL,
    device_id        TEXT NOT NULL,
    member_seq       INTEGER NOT NULL,
    member_head_hash BLOB NOT NULL,
    signature        BLOB NOT NULL,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (vault_id, key_epoch, device_id)
);

CREATE TABLE events (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         BLOB NOT NULL,
    event_hash       BLOB NOT NULL,
    vault_id         BLOB NOT NULL,
    device_id        TEXT NOT NULL,
    counter          INTEGER NOT NULL,
    lamport          INTEGER NOT NULL,
    key_epoch        INTEGER NOT NULL,
    prev_hash        BLOB NOT NULL,
    nonce            BLOB NOT NULL,
    ciphertext       BLOB NOT NULL,
    signature        BLOB NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_events_vault_device_counter ON events(vault_id, device_id, counter);
CREATE UNIQUE INDEX idx_events_vault_device_event_id ON events(vault_id, device_id, event_id);
CREATE INDEX idx_events_vault_seq ON events(vault_id, seq);
CREATE INDEX idx_events_vault_device ON events(vault_id, device_id);

CREATE TABLE event_heads (
    vault_id      BLOB NOT NULL,
    device_id     TEXT NOT NULL,
    last_counter  INTEGER NOT NULL,
    last_hash     BLOB NOT NULL,
    PRIMARY KEY (vault_id, device_id)
);

CREATE TABLE snapshots (
    snapshot_id          BLOB PRIMARY KEY,
    vault_id             BLOB NOT NULL,
    base_seq             INTEGER NOT NULL,
    member_seq           INTEGER NOT NULL,
    member_head_hash     BLOB NOT NULL,
    base_counter_map     BLOB NOT NULL,
    head_hash_map        BLOB NOT NULL,
    lamport_at_snapshot  INTEGER NOT NULL,
    key_epoch            INTEGER NOT NULL,
    nonce                BLOB NOT NULL,
    ciphertext           BLOB NOT NULL,
    signature            BLOB NOT NULL,
    created_by_device_id TEXT NOT NULL,
    created_at           TEXT NOT NULL
);

CREATE INDEX idx_snapshots_vault_seq ON snapshots(vault_id, base_seq DESC);

CREATE TABLE used_nonces (
    nonce_type   TEXT NOT NULL,
    vault_id     BLOB NOT NULL,
    device_id    TEXT NOT NULL,
    nonce        BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (nonce_type, vault_id, device_id, nonce)
);
