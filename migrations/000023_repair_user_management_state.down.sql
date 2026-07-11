-- Data repaired by the up migration is intentionally not re-marked as a
-- temporary password. Only restore the version-22 column default.
ALTER TABLE app_user
    ALTER COLUMN must_change_password SET DEFAULT 1;
