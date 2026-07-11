DROP TABLE risk_score_history;

ALTER TABLE risk
    DROP KEY uk_risk_project_id,
    DROP COLUMN scored_at,
    DROP COLUMN score_factors_json,
    DROP COLUMN score_model_version,
    DROP COLUMN score_level;
