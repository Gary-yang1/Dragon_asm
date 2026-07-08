-- M1-3: asset_relation — directed relationships between two assets within one
-- project (e.g. domain→subdomain "contains", subdomain→ip "resolves_to"). This is
-- the relation base layer for the later discovery pipeline and the exposure
-- graph; it carries no visualization or discovery-engine concerns.
--
-- Soft-delete convention matches asset/project: deleted_at is NOT NULL with the
-- '1970-01-01 00:00:00.000' sentinel; a row is "live" while deleted_at equals it,
-- and the unique key includes deleted_at so a soft-deleted relation never blocks
-- re-creating the same (from, to, type) edge.
--
-- Endpoints are scoped to the project: every relation row carries the same
-- tenant_id/org_id/project_id as both endpoints, enforced at the DB layer by TWO
-- composite foreign keys referencing asset(tenant_id, org_id, project_id, id).
-- That requires asset to expose a unique key on that 4-tuple (id is already
-- globally unique, so the combination is unique); we add it here.

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