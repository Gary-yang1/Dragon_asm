-- EXT-03: turn discovery_callback into a durable, recoverable inbox.
ALTER TABLE discovery_callback
    ADD COLUMN schema_version VARCHAR(16) NOT NULL DEFAULT '1.0' AFTER seq,
    ADD COLUMN observed_at DATETIME(3) NULL AFTER status,
    ADD COLUMN payload_json JSON NULL AFTER payload_hash,
    ADD COLUMN payload_size INT UNSIGNED NOT NULL DEFAULT 0 AFTER payload_json,
    ADD COLUMN ingest_status VARCHAR(16) NOT NULL DEFAULT 'pending' AFTER enqueued_at,
    ADD COLUMN ingest_attempt INT UNSIGNED NOT NULL DEFAULT 0 AFTER ingest_status,
    ADD COLUMN ingest_error VARCHAR(1024) NOT NULL DEFAULT '' AFTER ingest_attempt,
    ADD COLUMN processed_at DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000' AFTER ingest_error;

UPDATE discovery_callback
SET payload_json = JSON_OBJECT(),
    ingest_status = 'processed',
    processed_at = CASE
        WHEN enqueued_at = '1970-01-01 00:00:00.000' THEN received_at
        ELSE enqueued_at
    END
WHERE payload_json IS NULL;

ALTER TABLE discovery_callback
    MODIFY COLUMN payload_json JSON NOT NULL,
    ADD KEY idx_discovery_callback_pending (ingest_status, received_at, deleted_at),
    ADD CONSTRAINT chk_discovery_callback_payload_size
        CHECK (payload_size <= 4194304),
    ADD CONSTRAINT chk_discovery_callback_ingest_status
        CHECK (ingest_status IN ('pending', 'processing', 'processed', 'failed'));

-- Keep retention archives contract-compatible so a processed inbox row can be
-- archived without losing its bounded payload and ingest state.
ALTER TABLE discovery_callback_archive
    ADD COLUMN schema_version VARCHAR(16) NOT NULL DEFAULT '1.0' AFTER seq,
    ADD COLUMN observed_at DATETIME(3) NULL AFTER status,
    ADD COLUMN payload_json JSON NULL AFTER payload_hash,
    ADD COLUMN payload_size INT UNSIGNED NOT NULL DEFAULT 0 AFTER payload_json,
    ADD COLUMN ingest_status VARCHAR(16) NOT NULL DEFAULT 'processed' AFTER enqueued_at,
    ADD COLUMN ingest_attempt INT UNSIGNED NOT NULL DEFAULT 0 AFTER ingest_status,
    ADD COLUMN ingest_error VARCHAR(1024) NOT NULL DEFAULT '' AFTER ingest_attempt,
    ADD COLUMN processed_at DATETIME(3) NOT NULL DEFAULT '1970-01-01 00:00:00.000' AFTER ingest_error;

UPDATE discovery_callback_archive
SET payload_json = JSON_OBJECT(),
    processed_at = CASE
        WHEN enqueued_at = '1970-01-01 00:00:00.000' THEN received_at
        ELSE enqueued_at
    END
WHERE payload_json IS NULL;

ALTER TABLE discovery_callback_archive
    MODIFY COLUMN payload_json JSON NOT NULL,
    ADD CONSTRAINT chk_discovery_callback_archive_payload_size
        CHECK (payload_size <= 4194304),
    ADD CONSTRAINT chk_discovery_callback_archive_ingest_status
        CHECK (ingest_status IN ('processed', 'failed'));
