package job

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"baiyan/internal/contract"
)

var ErrNotFound = errors.New("baiyan job: not found")

type Store interface {
	Save(record Record) error
	Get(jobID string) (Record, error)
	ListRecoverable() ([]Record, error)
}

// CallbackCheckpointStore makes callback sequence delivery crash-safe without
// exposing callback persistence through the public Engine HTTP API.
type CallbackCheckpointStore interface {
	PrepareCallback(runID uint64, batch contract.CallbackBatch) (contract.CallbackBatch, bool, error)
	AcknowledgeCallback(runID, seq uint64) error
}

type FileStore struct {
	dir string
	mu  sync.RWMutex
}

func NewFileStore(dir string) (*FileStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("baiyan job: store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) Save(record Record) error {
	if !validJobID(record.JobID) {
		return errors.New("baiyan job: invalid job id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.getUnlocked(record.JobID); err == nil {
		mergeCallbackCheckpoint(&record, existing)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.saveUnlocked(record)
}

func (s *FileStore) saveUnlocked(record Record) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, record.JobID+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path(record.JobID))
}

func (s *FileStore) Get(jobID string) (Record, error) {
	if !validJobID(jobID) {
		return Record{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getUnlocked(jobID)
}

func (s *FileStore) getUnlocked(jobID string) (Record, error) {
	raw, err := os.ReadFile(s.path(jobID))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(raw, &record); err != nil {
		return Record{}, fmt.Errorf("baiyan job: corrupt record: %w", err)
	}
	return record, nil
}

// PrepareCallback persists an immutable pending batch before network delivery.
// On recovery, acknowledged sequences are skipped and an unacknowledged batch
// is replayed byte-for-byte from the stored structured value.
func (s *FileStore) PrepareCallback(runID uint64, batch contract.CallbackBatch) (contract.CallbackBatch, bool, error) {
	jobID := "job-" + strconv.FormatUint(runID, 10)
	if batch.RunID != runID || batch.Seq == 0 {
		return contract.CallbackBatch{}, false, errors.New("baiyan job: invalid callback checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.getUnlocked(jobID)
	if err != nil {
		return contract.CallbackBatch{}, false, err
	}
	if batch.Seq <= record.LastCallbackSeq {
		return contract.CallbackBatch{}, true, nil
	}
	if record.PendingCallback != nil {
		if record.PendingCallback.Seq != batch.Seq {
			return contract.CallbackBatch{}, false, errors.New("baiyan job: callback checkpoint sequence mismatch")
		}
		return *record.PendingCallback, false, nil
	}
	if batch.Seq != record.LastCallbackSeq+1 {
		return contract.CallbackBatch{}, false, errors.New("baiyan job: callback checkpoint sequence gap")
	}
	checkpoint := batch
	record.PendingCallback = &checkpoint
	if err := s.saveUnlocked(record); err != nil {
		return contract.CallbackBatch{}, false, err
	}
	return checkpoint, false, nil
}

// AcknowledgeCallback advances the durable sequence only after a successful
// callback response.
func (s *FileStore) AcknowledgeCallback(runID, seq uint64) error {
	jobID := "job-" + strconv.FormatUint(runID, 10)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.getUnlocked(jobID)
	if err != nil {
		return err
	}
	if seq <= record.LastCallbackSeq {
		return nil
	}
	if record.PendingCallback == nil || record.PendingCallback.Seq != seq || seq != record.LastCallbackSeq+1 {
		return errors.New("baiyan job: callback acknowledgement mismatch")
	}
	record.LastCallbackSeq = seq
	record.PendingCallback = nil
	return s.saveUnlocked(record)
}

func mergeCallbackCheckpoint(record *Record, existing Record) {
	if existing.LastCallbackSeq > record.LastCallbackSeq {
		record.LastCallbackSeq = existing.LastCallbackSeq
	}
	if record.PendingCallback != nil && record.PendingCallback.Seq <= record.LastCallbackSeq {
		record.PendingCallback = nil
	}
	if existing.PendingCallback != nil && record.LastCallbackSeq < existing.PendingCallback.Seq {
		pending := *existing.PendingCallback
		record.PendingCallback = &pending
	}
}

func (s *FileStore) ListRecoverable() ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		if record.Status == StatusQueued || record.Status == StatusRunning {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.Before(records[j].CreatedAt) })
	return records, nil
}

func (s *FileStore) path(jobID string) string { return filepath.Join(s.dir, jobID+".json") }

func validJobID(value string) bool {
	if !strings.HasPrefix(value, "job-") || len(value) > 96 {
		return false
	}
	numeric := strings.TrimPrefix(value, "job-")
	if numeric == "" {
		return false
	}
	for _, r := range numeric {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
