-- The merge in the up migration is not reversible: the soft-deleted duplicates
-- remain in the table, but which references used to point at them is not
-- recorded. Rolling back the version is allowed and leaves the merged data.
SELECT 1;
