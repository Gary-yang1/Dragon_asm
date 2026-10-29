package discovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

type engineProjectResolver interface {
	Resolve(context.Context, engineProjectAPI, uint64) (int, error)
}

type sqlEngineProjectResolver struct{ db *sql.DB }

// Resolve owns local identity and persistence; engineProjectAPI owns the remote
// protocol. Retrying ensure with the same identity cannot create another project.
func (r *sqlEngineProjectResolver) Resolve(ctx context.Context, a engineProjectAPI, projectID uint64) (int, error) {
	endpoint := sha256.Sum256([]byte(a.projectEndpoint()))
	key := hex.EncodeToString(endpoint[:])
	var remoteID sql.NullInt64
	var name, description string
	var started bool
	read := func() error {
		return r.db.QueryRowContext(ctx, `SELECT engine_project_id, remote_name, remote_description, creation_started FROM engine_project_binding WHERE project_id=? AND endpoint_key=?`, projectID, key).Scan(&remoteID, &name, &description, &started)
	}
	if err := read(); errors.Is(err, sql.ErrNoRows) {
		var projectName string
		if err := r.db.QueryRowContext(ctx, `SELECT name FROM project WHERE id=? AND deleted_at='1970-01-01 00:00:00'`, projectID).Scan(&projectName); err != nil {
			return 0, ErrEngineProjectSetup
		}
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return 0, ErrEngineProjectSetup
		}
		// Keep a human-readable label while using a random deployment-local identity.
		runes := []rune(projectName)
		if len(runes) > 120 {
			runes = runes[:120]
		}
		name = "ASM · " + string(runes) + " [" + hex.EncodeToString(token) + "]"
		description = fmt.Sprintf("由 ASM 自动管理，平台项目 #%d。", projectID)
		if _, err := r.db.ExecContext(ctx, `INSERT INTO engine_project_binding (project_id, endpoint_key, remote_name, remote_description) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE project_id=project_id`, projectID, key, name, description); err != nil {
			return 0, ErrEngineProjectSetup
		}
		if err := read(); err != nil {
			return 0, ErrEngineProjectSetup
		}
	} else if err != nil {
		return 0, ErrEngineProjectSetup
	}
	if remoteID.Valid && remoteID.Int64 > 0 {
		return int(remoteID.Int64), nil
	}
	var project managedActiveProject
	var err error
	if started {
		// A historical non-idempotent request may still have completed remotely.
		// Never translate its uncertain result into a fresh ensure identity.
		project, err = a.findManagedProject(ctx, name, description)
		if err == nil && project.ID == 0 {
			err = ErrEngineProjectPending
		}
	} else {
		identity := sha256.Sum256([]byte(name))
		project, err = a.ensureManagedProject(ctx, "asm:"+hex.EncodeToString(identity[:]), name, description)
	}
	if err != nil {
		return 0, err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE engine_project_binding SET engine_project_id=? WHERE project_id=? AND endpoint_key=? AND (engine_project_id IS NULL OR engine_project_id=?)`, project.ID, projectID, key, project.ID)
	if err != nil {
		return 0, ErrEngineProjectSetup
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		if err := read(); err != nil || !remoteID.Valid || remoteID.Int64 != int64(project.ID) {
			return 0, ErrEngineProjectSetup
		}
	}
	return project.ID, nil
}
