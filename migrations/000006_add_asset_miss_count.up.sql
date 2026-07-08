-- M1-4: asset lifecycle — track consecutive discovery "misses" so the lifecycle
-- worker can flip a stale asset active -> inactive after N misses (no physical
-- delete). miss_count is incremented by the lifecycle/miss recorder and reset to
-- 0 on a discovery hit; the status transition itself is audited by the service.
--
-- Kept as a non-null default-0 column so existing rows are immediately eligible
-- for lifecycle tracking without a backfill.

ALTER TABLE asset
    ADD COLUMN miss_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER confidence;