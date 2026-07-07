-- M1-1: asset table (MySQL 8) — the shared asset base for import, discovery,
-- exposure, risk and ticketing.
--
-- Soft-delete convention matches project/user: deleted_at is NOT NULL with a
-- sentinel default of '1970-01-01 00:00:00.000'. A row is "live" while deleted_at
-- equals that sentinel, and the unique key includes deleted_at so a soft-deleted
-- row never blocks re-creating one with the same natural key.
--
-- asset_key is the normalized, type-prefixed natural key (e.g. "domain:example.com",
-- "ip:192.168.0.1", "port:192.168.0.1:443"). Normalization + the type prefix happen
-- in the service layer, so uniqueness is enforced per project on the normalized key.
-- confidence is 0..100. first_seen/last_seen track discovery timestamps.

CREATE TABLE asset (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT '',
    org_id        VARCHAR(64)   NOT NULL DEFAULT '',
    project_id    BIGINT UNSIGNED NOT NULL,
    asset_type    VARCHAR(32)   NOT NULL,
    asset_key     VARCHAR(512)  NOT NULL,
    display_name  VARCHAR(255)  NOT NULL DEFAULT '',
    value         VARCHAR(1024) NOT NULL DEFAULT '',
    source        VARCHAR(64)   NOT NULL DEFAULT '',
    owner         VARCHAR(64)   NOT NULL DEFAULT '',
    business_unit VARCHAR(128)  NOT NULL DEFAULT '',
    confidence    TINYINT UNSIGNED NOT NULL DEFAULT 100,
    status        VARCHAR(32)   NOT NULL DEFAULT 'active',
    first_seen    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen     DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_asset_key (project_id, asset_key, deleted_at),
    KEY idx_asset_project_type (project_id, asset_type),
    KEY idx_asset_project_status (project_id, status),
    KEY idx_asset_last_seen (last_seen),
    CONSTRAINT fk_asset_project FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_type CHECK (asset_type IN ('domain', 'subdomain', 'ip', 'port', 'service', 'web', 'certificate', 'cloud_resource', 'third_party')),
    CONSTRAINT chk_asset_status CHECK (status IN ('active', 'inactive', 'ignored', 'deleted')),
    CONSTRAINT chk_asset_confidence CHECK (confidence <= 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
