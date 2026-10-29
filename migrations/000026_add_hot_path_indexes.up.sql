-- Indexes for query shapes that currently full-scan or filesort.
--
-- Each entry names the query it serves and was verified with EXPLAIN ANALYZE on
-- MySQL 8.0 against seeded data: the optimizer actually chooses every index
-- below. Candidates that the optimizer declined were dropped rather than shipped,
-- because an unused index still costs write amplification on every insert.
--
-- All are additive non-unique secondary indexes: no column, constraint, or row is
-- modified, so this is safe to run online on a populated database.

-- Retention pruning (platform/retention/repository.go): WHERE detected_at < ?
-- ORDER BY detected_at, id. All three existing change_event secondaries lead with
-- tenant_id, so the prune job full-scanned the highest-growth table — it got
-- slower exactly as the table it exists to trim grew.
ALTER TABLE change_event
    ADD KEY idx_change_event_detected (detected_at, id);

-- ListRunningTaskRunsForReconcile (query/discovery.sql): WHERE status = 'running'
-- ... ORDER BY dispatched_at, id, deliberately cross-project. Every other
-- task_run index leads with project_id, so the reconcile worker full-scanned an
-- ever-growing table on each tick.
ALTER TABLE task_run
    ADD KEY idx_task_run_status_dispatched (status, dispatched_at, id);

-- ClaimPendingReportExport (query/report.sql): WHERE status = 'pending' AND
-- deleted_at = ? ORDER BY id, cross-project. idx_report_export_project_status
-- leads with project_id and cannot serve it.
ALTER TABLE report_export
    ADD KEY idx_report_export_status_id (status, deleted_at, id);

-- ReportRiskTrend / ReportFixedRiskTrend (query/report.sql): a project_id
-- equality plus a date range over first_seen / fixed_at. Risk had no index on
-- either column, so every dashboard render scanned all of the project's risks.
-- Measured: 3,000 rows examined instead of 40,000 for a 30-day window.
ALTER TABLE risk
    ADD KEY idx_risk_project_first_seen (project_id, first_seen),
    ADD KEY idx_risk_project_fixed_at (project_id, fixed_at);
