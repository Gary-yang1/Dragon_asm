-- Reverse M1-3: drop the relation table, then the asset scope unique key it added.
-- Order matters: the table must go first so its composite FKs no longer reference
-- the asset unique key before that key is dropped.

DROP TABLE IF EXISTS asset_relation;

ALTER TABLE asset DROP INDEX uk_asset_scope_id;