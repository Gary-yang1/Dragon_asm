CREATE TABLE discovery_observation (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id       VARCHAR(64)   NOT NULL,
    org_id          VARCHAR(64)   NOT NULL,
    project_id      BIGINT UNSIGNED NOT NULL,
    run_id          BIGINT UNSIGNED NOT NULL,
    seq             BIGINT UNSIGNED NOT NULL,
    kind            VARCHAR(32)   NOT NULL,
    natural_key     VARCHAR(512)  NOT NULL,
    client_ref      VARCHAR(128)  NOT NULL DEFAULT '',
    provider        VARCHAR(64)   NOT NULL,
    capability      VARCHAR(64)   NOT NULL,
    observed_at     DATETIME(3)   NOT NULL,
    confidence      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    active_probe    BOOLEAN       NOT NULL DEFAULT FALSE,
    evidence_hash   CHAR(64)      NOT NULL,
    evidence_ref    VARCHAR(512)  NOT NULL DEFAULT '',
    normalized_json JSON          NOT NULL,
    normalized_size INT UNSIGNED  NOT NULL,
    ingest_status   VARCHAR(16)   NOT NULL DEFAULT 'observed',
    ingest_error    VARCHAR(1024) NOT NULL DEFAULT '',
    created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at      DATETIME(3)   NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    PRIMARY KEY (id),
    UNIQUE KEY uk_discovery_observation_fact
        (project_id, run_id, kind, natural_key, provider, deleted_at),
    KEY idx_discovery_observation_run (project_id, run_id, seq, id),
    KEY idx_discovery_observation_lifecycle (project_id, kind, natural_key, observed_at),
    CONSTRAINT fk_discovery_observation_run_project
        FOREIGN KEY (project_id, run_id) REFERENCES task_run (project_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_discovery_observation_kind
        CHECK (kind IN ('asset', 'relation', 'exposure', 'provider_error')),
    CONSTRAINT chk_discovery_observation_confidence CHECK (confidence <= 100),
    CONSTRAINT chk_discovery_observation_normalized_size CHECK (normalized_size <= 65536),
    CONSTRAINT chk_discovery_observation_ingest_status
        CHECK (ingest_status IN ('observed', 'materialized', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
