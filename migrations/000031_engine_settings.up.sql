-- Configuration history is deployment-wide, writeable only by system admins.
-- All connection/provider secrets are encrypted as a single authenticated payload.
CREATE TABLE engine_settings_version (
    version BIGINT UNSIGNED NOT NULL,
    encrypted_payload MEDIUMBLOB NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (version)
) ENGINE=InnoDB;
CREATE TABLE engine_settings_head (
    id TINYINT UNSIGNED NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT chk_engine_settings_singleton CHECK (id = 1)
) ENGINE=InnoDB;
INSERT INTO engine_settings_head (id, version) VALUES (1, 0);
CREATE TABLE engine_run_settings (
    project_id BIGINT UNSIGNED NOT NULL,
    run_id BIGINT UNSIGNED NOT NULL,
    version BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (project_id, run_id),
    CONSTRAINT fk_engine_run_settings_run FOREIGN KEY (project_id, run_id) REFERENCES task_run(project_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_engine_run_settings_version FOREIGN KEY (version) REFERENCES engine_settings_version(version)
) ENGINE=InnoDB;
