ALTER TABLE discovery_observation ADD UNIQUE KEY uk_observation_project_run_id (project_id, run_id, id);
CREATE TABLE web_network_enrichment (
    observation_id BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    run_id BIGINT UNSIGNED NOT NULL,
    config_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_hash CHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    lease_token CHAR(32) NOT NULL DEFAULT '',
    lease_until DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000',
    next_attempt_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    result_json JSON NULL,
    error_summary VARCHAR(512) NOT NULL DEFAULT '',
    enriched_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (observation_id),
    KEY idx_web_enrichment_work (state,next_attempt_at,observation_id),
    KEY idx_web_enrichment_run (project_id,run_id),
    CONSTRAINT fk_web_enrichment_observation FOREIGN KEY (project_id,run_id,observation_id)
        REFERENCES discovery_observation(project_id,run_id,id) ON DELETE CASCADE,
    CONSTRAINT chk_web_enrichment_state CHECK (state IN ('pending','running','complete','failed')),
    CONSTRAINT chk_web_enrichment_attempts CHECK (attempts <= 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
