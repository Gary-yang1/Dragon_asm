-- Network attribution recorded by the engine's DNS stage: an address that is a
-- CDN edge, or a name served through one. It is evidence about an asset, not a
-- property of every asset, so it lives beside the asset table rather than in it.
--
-- Only identified judgements are stored, and a later run that cannot tell does
-- not erase one: "unknown" is not "no". The newest identification refreshes the
-- provider, evidence and rule version.
CREATE TABLE asset_network_attribution (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id      VARCHAR(64)     NOT NULL,
    org_id         VARCHAR(64)     NOT NULL,
    project_id     BIGINT UNSIGNED NOT NULL,
    asset_id       BIGINT UNSIGNED NOT NULL,
    role           VARCHAR(32)     NOT NULL,
    provider       VARCHAR(128)    NOT NULL DEFAULT '',
    evidence       VARCHAR(1024)   NOT NULL DEFAULT '',
    rule_version   VARCHAR(64)     NOT NULL,
    source_run_id  BIGINT UNSIGNED NOT NULL,
    observed_at    DATETIME(3)     NOT NULL,
    created_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_asset_network_attribution (project_id, asset_id),
    KEY idx_asset_network_attribution_role (project_id, role),
    CONSTRAINT chk_asset_network_attribution_role CHECK (role IN ('cdn_edge', 'cdn_served')),
    CONSTRAINT fk_asset_network_attribution_asset FOREIGN KEY (tenant_id, org_id, project_id, asset_id)
        REFERENCES asset (tenant_id, org_id, project_id, id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
