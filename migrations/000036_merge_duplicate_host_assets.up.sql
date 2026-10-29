-- Active web probing used to record every website host as a `domain` asset,
-- while passive collection records hosts beneath a scope root as `subdomain`.
-- The same host therefore appeared twice in the asset list. Fold each such
-- `domain` duplicate into its live `subdomain` twin: move every reference to
-- the twin, keep any management field only the duplicate carried, then
-- soft-delete the duplicate.
--
-- A value that is a scope domain root or a project-profile domain is left
-- alone: there the `domain` record is the authoritative one, so folding it into
-- a `subdomain` would invert the classification.
--
-- A regular work table is used because MySQL cannot reference one TEMPORARY
-- table twice in a statement.
CREATE TABLE asset_merge_000036 (
    dup_id     BIGINT UNSIGNED NOT NULL,
    keep_id    BIGINT UNSIGNED NOT NULL,
    project_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (dup_id),
    KEY idx_asset_merge_keep (keep_id)
) ENGINE=InnoDB;

INSERT INTO asset_merge_000036 (dup_id, keep_id, project_id)
SELECT d.id, s.id, d.project_id
FROM asset d
JOIN asset s
  ON s.project_id = d.project_id
 AND s.asset_type = 'subdomain'
 AND s.value = d.value
 AND s.deleted_at = '1970-01-01 00:00:00.000'
WHERE d.asset_type = 'domain'
  AND d.deleted_at = '1970-01-01 00:00:00.000'
  AND NOT EXISTS (
      SELECT 1 FROM scope_target t
      WHERE t.project_id = d.project_id AND t.target_type = 'domain' AND t.target_value = d.value
  )
  AND NOT EXISTS (
      SELECT 1 FROM project_domain_profile p WHERE p.project_id = d.project_id AND p.asset_id = d.id
  );

-- Relations whose re-pointed form already exists on the twin are retired first,
-- so the move below cannot violate uk_relation.
UPDATE asset_relation r
JOIN asset_merge_000036 m ON m.dup_id = r.from_asset_id AND m.project_id = r.project_id
JOIN asset_relation k
  ON k.project_id = r.project_id
 AND k.from_asset_id = m.keep_id
 AND k.to_asset_id = r.to_asset_id
 AND k.relation_type = r.relation_type
 AND k.deleted_at = '1970-01-01 00:00:00.000'
SET r.deleted_at = NOW(3), r.updated_by = 'migration-000036'
WHERE r.deleted_at = '1970-01-01 00:00:00.000';

UPDATE asset_relation r
JOIN asset_merge_000036 m ON m.dup_id = r.from_asset_id AND m.project_id = r.project_id
SET r.from_asset_id = m.keep_id, r.updated_by = 'migration-000036'
WHERE r.deleted_at = '1970-01-01 00:00:00.000';

UPDATE asset_relation r
JOIN asset_merge_000036 m ON m.dup_id = r.to_asset_id AND m.project_id = r.project_id
JOIN asset_relation k
  ON k.project_id = r.project_id
 AND k.from_asset_id = r.from_asset_id
 AND k.to_asset_id = m.keep_id
 AND k.relation_type = r.relation_type
 AND k.deleted_at = '1970-01-01 00:00:00.000'
SET r.deleted_at = NOW(3), r.updated_by = 'migration-000036'
WHERE r.deleted_at = '1970-01-01 00:00:00.000';

UPDATE asset_relation r
JOIN asset_merge_000036 m ON m.dup_id = r.to_asset_id AND m.project_id = r.project_id
SET r.to_asset_id = m.keep_id, r.updated_by = 'migration-000036'
WHERE r.deleted_at = '1970-01-01 00:00:00.000';

-- A relation the move turned into a self-loop carries no information.
UPDATE asset_relation r
JOIN asset_merge_000036 m ON m.keep_id = r.from_asset_id AND m.project_id = r.project_id
SET r.deleted_at = NOW(3), r.updated_by = 'migration-000036'
WHERE r.from_asset_id = r.to_asset_id AND r.deleted_at = '1970-01-01 00:00:00.000';

UPDATE exposure e
JOIN asset_merge_000036 m ON m.dup_id = e.asset_id AND m.project_id = e.project_id
SET e.asset_id = m.keep_id;

UPDATE risk r
JOIN asset_merge_000036 m ON m.dup_id = r.asset_id AND m.project_id = r.project_id
SET r.asset_id = m.keep_id;

UPDATE suppression_rule r
JOIN asset_merge_000036 m ON m.dup_id = r.asset_id AND m.project_id = r.project_id
SET r.asset_id = m.keep_id;

-- Keep what an operator set on the duplicate when the twin has nothing, and
-- the widest observation window of the two.
UPDATE asset s
JOIN asset_merge_000036 m ON m.keep_id = s.id
JOIN asset d ON d.id = m.dup_id
SET s.owner = IF(s.owner = '', d.owner, s.owner),
    s.business_unit = IF(s.business_unit = '', d.business_unit, s.business_unit),
    s.first_seen = LEAST(s.first_seen, d.first_seen),
    s.last_seen = GREATEST(s.last_seen, d.last_seen),
    s.confidence = GREATEST(s.confidence, d.confidence),
    s.updated_by = 'migration-000036';

UPDATE asset d
JOIN asset_merge_000036 m ON m.dup_id = d.id
SET d.deleted_at = NOW(3), d.updated_by = 'migration-000036';

DROP TABLE asset_merge_000036;
