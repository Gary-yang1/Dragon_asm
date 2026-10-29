CREATE TABLE engine_project_binding (
    project_id BIGINT UNSIGNED NOT NULL,
    endpoint_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    remote_name VARCHAR(255) NOT NULL,
    remote_description VARCHAR(512) NOT NULL,
    engine_project_id BIGINT UNSIGNED NULL,
    creation_started BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (project_id, endpoint_key),
    UNIQUE KEY uk_engine_remote_name (endpoint_key, remote_name),
    CONSTRAINT fk_engine_binding_project FOREIGN KEY (project_id) REFERENCES project(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
