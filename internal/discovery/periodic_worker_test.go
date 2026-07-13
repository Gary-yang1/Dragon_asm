package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCallbackRecoverer struct {
	limit int32
	count int
	err   error
}

func (f *fakeCallbackRecoverer) RecoverPendingCallbacks(_ context.Context, limit int32) (int, error) {
	f.limit = limit
	return f.count, f.err
}

type periodicRegistration struct {
	cronspec string
	task     *asynq.Task
	opts     []asynq.Option
}

type fakePeriodicRegistrar struct {
	registrations []periodicRegistration
	errAt         int
}

func (f *fakePeriodicRegistrar) Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error) {
	if f.errAt > 0 && len(f.registrations)+1 == f.errAt {
		return "", errors.New("register failed")
	}
	f.registrations = append(f.registrations, periodicRegistration{cronspec: cronspec, task: task, opts: opts})
	return task.Type(), nil
}

func TestRecoverCallbacksHandler(t *testing.T) {
	recoverer := &fakeCallbackRecoverer{count: 3}
	body, err := json.Marshal(RecoverCallbacksPayload{Limit: 25})
	require.NoError(t, err)
	err = NewRecoverCallbacksHandler(recoverer, nil).Handle(context.Background(), asynq.NewTask(TaskTypeRecoverCallbacks, body))
	require.NoError(t, err)
	assert.Equal(t, int32(25), recoverer.limit)
}

func TestRegisterPeriodicTasksIsObservable(t *testing.T) {
	registrar := &fakePeriodicRegistrar{}
	entries, err := RegisterPeriodicTasks(registrar, "critical")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	require.Len(t, registrar.registrations, 2)
	assert.Equal(t, "@every 30s", registrar.registrations[0].cronspec)
	assert.Equal(t, TaskTypeRecoverCallbacks, registrar.registrations[0].task.Type())
	assert.Equal(t, "@every 1m", registrar.registrations[1].cronspec)
	assert.Equal(t, TaskTypeReconcileTimedOutRun, registrar.registrations[1].task.Type())
	for _, registration := range registrar.registrations {
		values := map[asynq.OptionType]any{}
		for _, option := range registration.opts {
			values[option.Type()] = option.Value()
		}
		assert.Equal(t, "critical", values[asynq.QueueOpt])
		assert.Equal(t, 5, values[asynq.MaxRetryOpt])
	}
}
