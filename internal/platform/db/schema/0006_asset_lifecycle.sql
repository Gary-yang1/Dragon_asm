-- sqlc schema for M1-4 asset lifecycle. Kept in sync with
-- migrations/000006_add_asset_miss_count.up.sql. sqlc reads this to generate the
-- miss_count field on Asset.

ALTER TABLE asset
    ADD COLUMN miss_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER confidence;