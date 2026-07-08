-- sqlc schema for the asset_relation domain. Kept in sync with
-- migrations/000005_create_asset_relation.up.sql. sqlc reads this to generate
-- types.

-- The composite FK to asset requires a unique key on asset's scope+id; id is
-- already globally unique so the 4-tuple is unique. Mirrors the migration ALTER.
ALTER TABLE asset
    ADD UNIQUE KEY uk_asset_scope_id (tenant_id, org_id, project_id, id);

CREATE TABLE asset_relation (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id     VARCHAR(64)   NOT NULL DEFAULT '',
    org_id        VARCHAR(64)   NOT NULL DEFAULT '',
    project_id    BIGINT UNSIGNED NOT NULL,
    from_asset_id BIGINT UNSIGNED NOT NULL,
    to_asset_id   BIGINT UNSIGNED NOT NULL,
    relation_type VARCHAR(64)   NOT NULL,
    source        VARCHAR(64)   NOT NULL DEFAULT '',
    confidence    TINYINT UNSIGNED NOT NULL DEFAULT 100,
    first_seen    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen     DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    VARCHAR(64)   NOT NULL DEFAULT '',
    updated_by    VARCHAR(64)   NOT NULL DEFAULT '',
    deleted_at    DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_relation (project_id, from_asset_id, to_asset_id, relation_type, deleted_at),
    KEY idx_relation_from (project_id, from_asset_id),
    KEY idx_relation_to (project_id, to_asset_id),
    CONSTRAINT chk_relation_confidence CHECK (confidence <= 100),
    CONSTRAINT chk_relation_type CHECK (relation_type IN
        ('contains', 'resolves_to', 'redirects_to', 'cert_binding', 'references')),
    CONSTRAINT fk_relation_from FOREIGN KEY (tenant_id, org_id, project_id, from_asset_id)
        REFERENCES asset (tenant_id, org_id, project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_relation_to FOREIGN KEY (tenant_id, org_id, project_id, to_asset_id)
        REFERENCES asset (tenant_id, org_id, project_id, id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;