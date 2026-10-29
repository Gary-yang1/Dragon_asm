-- Intentionally non-shrinking rollback: older application versions also accept
-- MEDIUMTEXT, but existing audit snapshots may now exceed TEXT's 65,535-byte
-- limit. Preserve all audit records and both widened columns in both tables.
-- This migration MUST NOT cast, truncate, delete, or silently discard snapshots.
-- A physical type downgrade is a separate maintenance operation requiring a
-- byte-length check of both tables and a verified lossless archival procedure.
SELECT 'Audit snapshot columns remain MEDIUMTEXT to preserve complete audit records' AS rollback_notice;
