package discovery

import (
	"context"
	"database/sql"
	"os"
	"time"
)

// OpenEngineSettings enables managed settings only when the deployment supplies a protected key file.
func OpenEngineSettings(ctx context.Context, db *sql.DB, baseline EngineSettings) (*EngineSettingsStore, error) {
	path := os.Getenv("ENGINE_SETTINGS_KEY_FILE")
	if path == "" {
		return nil, nil
	}
	key, err := LoadEngineSettingsKey(path)
	if err != nil {
		return nil, err
	}
	store, err := NewEngineSettingsStore(db, key)
	if err != nil {
		return nil, err
	}
	initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = store.Bootstrap(initCtx, baseline); err != nil {
		return nil, err
	}
	return store, nil
}

// WithEngineSettings enables version-bound routing without changing task authorization.
func WithEngineSettings(store *EngineSettingsStore) ServiceOption {
	return func(s *Service) { s.engineSettings = store }
}
func (s *Service) serviceWithSettings(snapshot EngineSettingsSnapshot) *Service {
	out := *s
	out.engineSettings = nil
	out.engineConfigVersion = snapshot.Version
	out.activePolicy = snapshot.Settings.Policy
	out.engineRouter, _ = snapshot.Router()
	return &out
}
func (s *Service) withLatestSettings(ctx context.Context) (*Service, error) {
	snapshot, err := s.engineSettings.Latest(ctx)
	if err != nil {
		return nil, err
	}
	return s.serviceWithSettings(snapshot), nil
}
func (s *Service) withRunSettings(ctx context.Context, projectID, runID uint64) (*Service, error) {
	snapshot, err := s.engineSettings.ForRun(ctx, projectID, runID)
	if err != nil {
		return nil, err
	}
	return s.serviceWithSettings(snapshot), nil
}
