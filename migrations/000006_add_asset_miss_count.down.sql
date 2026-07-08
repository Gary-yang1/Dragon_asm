-- Reverse M1-4: drop the miss_count column. Safe because no index or constraint
-- references it.

ALTER TABLE asset DROP COLUMN miss_count;