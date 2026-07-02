// Package audit provides append-only audit logging for all security-relevant
// operations in the ASM platform. Callers build an Event and call Service.Record;
// the service redacts sensitive fields, marshals before/after/metadata to JSON,
// and persists the entry via the Repository.
package audit

// ActorType identifies what kind of principal performed the action.
type ActorType string

// ActorUser is a human user; ActorSystem is an internal scheduler or worker;
// ActorService is an external service calling the API.
const (
	ActorUser    ActorType = "user"
	ActorSystem  ActorType = "system"
	ActorService ActorType = "service"
)

// Result of the audited operation.
type Result string

// ResultSuccess means the operation completed without error; ResultFailure means it did not.
const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// Event carries everything needed to write one audit_log row.
//
// Before, After, and Metadata accept any JSON-serialisable value (map[string]any,
// structs, slices, …). The Service redacts sensitive keys and marshals them to
// JSON before writing. Pass nil to omit the field (stored as NULL).
//
// ProjectID = 0 marks a platform-level event (login, system operation) with no
// project context.
type Event struct {
	TenantID     string
	OrgID        string
	ProjectID    uint64
	ActorID      string
	ActorType    ActorType
	Action       string
	ResourceType string
	ResourceID   string
	Result       Result
	IP           string
	UserAgent    string
	RequestID    string
	Before       any
	After        any
	Metadata     any
	ErrorCode    string
	ErrorMessage string
}
