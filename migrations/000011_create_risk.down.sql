DROP TABLE IF EXISTS risk;
DROP TABLE IF EXISTS vulnerability_definition;
ALTER TABLE exposure DROP KEY uk_exposure_project_id;
