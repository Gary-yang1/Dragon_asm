-- Reverse EXT-03 durable callback inbox fields.
ALTER TABLE discovery_callback_archive
    DROP CHECK chk_discovery_callback_archive_ingest_status,
    DROP CHECK chk_discovery_callback_archive_payload_size,
    DROP COLUMN processed_at,
    DROP COLUMN ingest_error,
    DROP COLUMN ingest_attempt,
    DROP COLUMN ingest_status,
    DROP COLUMN payload_size,
    DROP COLUMN payload_json,
    DROP COLUMN observed_at,
    DROP COLUMN schema_version;

ALTER TABLE discovery_callback
    DROP CHECK chk_discovery_callback_ingest_status,
    DROP CHECK chk_discovery_callback_payload_size,
    DROP KEY idx_discovery_callback_pending,
    DROP COLUMN processed_at,
    DROP COLUMN ingest_error,
    DROP COLUMN ingest_attempt,
    DROP COLUMN ingest_status,
    DROP COLUMN payload_size,
    DROP COLUMN payload_json,
    DROP COLUMN observed_at,
    DROP COLUMN schema_version;
