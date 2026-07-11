-- MP-2/MP-3: project workspace lifecycle and business profile.

ALTER TABLE project
    DROP CHECK chk_project_status,
    ADD CONSTRAINT chk_project_status CHECK (status IN ('draft', 'active', 'suspended', 'archived')),
    ADD UNIQUE KEY uk_project_scope_id (tenant_id, org_id, id);

CREATE TABLE project_subject (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id           VARCHAR(64)  NOT NULL,
    org_id              VARCHAR(64)  NOT NULL,
    project_id          BIGINT UNSIGNED NOT NULL,
    subject_key         VARCHAR(320) NOT NULL,
    subject_name        VARCHAR(255) NOT NULL,
    subject_type        VARCHAR(32)  NOT NULL DEFAULT 'company',
    registration_code   VARCHAR(64)  NOT NULL DEFAULT '',
    country_code        CHAR(2)      NOT NULL DEFAULT 'CN',
    region              VARCHAR(128) NOT NULL DEFAULT '',
    is_primary          BOOLEAN      NOT NULL DEFAULT FALSE,
    verification_status VARCHAR(32)  NOT NULL DEFAULT 'unverified',
    source              VARCHAR(64)  NOT NULL DEFAULT 'manual',
    verified_at         DATETIME(3)  NULL,
    evidence_summary    VARCHAR(1024) NOT NULL DEFAULT '',
    created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by          VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by          VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at          DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    primary_slot        TINYINT GENERATED ALWAYS AS (
        CASE WHEN is_primary = TRUE AND deleted_at = '1970-01-01 00:00:00.000' THEN 1 ELSE NULL END
    ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uk_project_subject_key (project_id, subject_key, deleted_at),
    UNIQUE KEY uk_project_subject_primary (project_id, primary_slot),
    UNIQUE KEY uk_project_subject_scope_id (tenant_id, org_id, project_id, id),
    KEY idx_project_subject_primary (project_id, is_primary, deleted_at),
    CONSTRAINT fk_project_subject_project FOREIGN KEY (tenant_id, org_id, project_id)
        REFERENCES project (tenant_id, org_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_project_subject_type CHECK (subject_type IN ('company', 'government', 'institution', 'individual', 'other')),
    CONSTRAINT chk_project_subject_verification CHECK (verification_status IN ('unverified', 'verified', 'mismatch'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE project_domain_profile (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id           VARCHAR(64)  NOT NULL,
    org_id              VARCHAR(64)  NOT NULL,
    project_id          BIGINT UNSIGNED NOT NULL,
    asset_id            BIGINT UNSIGNED NOT NULL,
    subject_id          BIGINT UNSIGNED NULL,
    is_primary          BOOLEAN      NOT NULL DEFAULT FALSE,
    ownership_status    VARCHAR(32)  NOT NULL DEFAULT 'unverified',
    source              VARCHAR(64)  NOT NULL DEFAULT 'manual',
    evidence_summary    VARCHAR(1024) NOT NULL DEFAULT '',
    created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by          VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by          VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at          DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    primary_slot        TINYINT GENERATED ALWAYS AS (
        CASE WHEN is_primary = TRUE AND deleted_at = '1970-01-01 00:00:00.000' THEN 1 ELSE NULL END
    ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uk_project_domain_asset (project_id, asset_id, deleted_at),
    UNIQUE KEY uk_project_domain_primary (project_id, primary_slot),
    UNIQUE KEY uk_project_domain_scope_id (tenant_id, org_id, project_id, id),
    KEY idx_project_domain_primary (project_id, is_primary, deleted_at),
    KEY idx_project_domain_subject (project_id, subject_id),
    CONSTRAINT fk_project_domain_project FOREIGN KEY (tenant_id, org_id, project_id)
        REFERENCES project (tenant_id, org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_project_domain_asset FOREIGN KEY (tenant_id, org_id, project_id, asset_id)
        REFERENCES asset (tenant_id, org_id, project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_project_domain_subject FOREIGN KEY (tenant_id, org_id, project_id, subject_id)
        REFERENCES project_subject (tenant_id, org_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_project_domain_ownership CHECK (ownership_status IN ('unverified', 'verified', 'mismatch'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE icp_filing (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id           VARCHAR(64)  NOT NULL,
    org_id              VARCHAR(64)  NOT NULL,
    project_id          BIGINT UNSIGNED NOT NULL,
    subject_id          BIGINT UNSIGNED NOT NULL,
    filing_no           VARCHAR(128) NOT NULL,
    filing_type         VARCHAR(32)  NOT NULL DEFAULT 'filing',
    website_name        VARCHAR(255) NOT NULL DEFAULT '',
    status              VARCHAR(32)  NOT NULL DEFAULT 'unverified',
    approved_at         DATETIME(3)  NULL,
    source              VARCHAR(64)  NOT NULL DEFAULT 'manual',
    verified_at         DATETIME(3)  NULL,
    evidence_summary    VARCHAR(1024) NOT NULL DEFAULT '',
    created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by          VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by          VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at          DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_icp_filing_no (project_id, filing_no, deleted_at),
    UNIQUE KEY uk_icp_filing_scope_id (tenant_id, org_id, project_id, id),
    KEY idx_icp_filing_subject (project_id, subject_id),
    CONSTRAINT fk_icp_filing_project FOREIGN KEY (tenant_id, org_id, project_id)
        REFERENCES project (tenant_id, org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_icp_filing_subject FOREIGN KEY (tenant_id, org_id, project_id, subject_id)
        REFERENCES project_subject (tenant_id, org_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT chk_icp_filing_type CHECK (filing_type IN ('filing', 'license')),
    CONSTRAINT chk_icp_filing_status CHECK (status IN ('unverified', 'valid', 'invalid', 'cancelled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE icp_filing_domain (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id           VARCHAR(64)  NOT NULL,
    org_id              VARCHAR(64)  NOT NULL,
    project_id          BIGINT UNSIGNED NOT NULL,
    filing_id           BIGINT UNSIGNED NOT NULL,
    domain_profile_id   BIGINT UNSIGNED NOT NULL,
    created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by          VARCHAR(64)  NOT NULL DEFAULT '',
    updated_by          VARCHAR(64)  NOT NULL DEFAULT '',
    deleted_at          DATETIME(3)  NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_icp_filing_domain (project_id, filing_id, domain_profile_id, deleted_at),
    KEY idx_icp_filing_domain_profile (project_id, domain_profile_id),
    CONSTRAINT fk_icp_filing_domain_project FOREIGN KEY (tenant_id, org_id, project_id)
        REFERENCES project (tenant_id, org_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_icp_filing_domain_filing FOREIGN KEY (tenant_id, org_id, project_id, filing_id)
        REFERENCES icp_filing (tenant_id, org_id, project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_icp_filing_domain_profile FOREIGN KEY (tenant_id, org_id, project_id, domain_profile_id)
        REFERENCES project_domain_profile (tenant_id, org_id, project_id, id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
