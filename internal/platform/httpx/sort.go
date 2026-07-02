package httpx

import (
	"fmt"
	"strings"
)

// SortDirection is the validated sort direction.
type SortDirection string

// SortAsc and SortDesc are the supported sort directions used by SortSpec.
const (
	SortAsc  SortDirection = "asc"
	SortDesc SortDirection = "desc"
)

// SortSpec is a client sort expression resolved and validated against a
// SortWhitelist. The zero value (empty Field) means "no sort requested".
type SortSpec struct {
	Field     string
	Direction SortDirection
}

// SortWhitelist validates client-supplied sort fields against an allowed set.
// Each business module builds its own whitelist; this type provides only the
// parsing/validation plumbing and is not bound to any table.
//
// Because every field is matched against an explicit allow-list, raw client
// input can never reach a SQL ORDER BY clause directly — unknown fields are
// rejected rather than interpolated.
type SortWhitelist struct {
	allowed map[string]struct{}
}

// NewSortWhitelist builds a whitelist from the given field names. Duplicate or
// blank names are ignored.
func NewSortWhitelist(fields ...string) *SortWhitelist {
	w := &SortWhitelist{allowed: make(map[string]struct{}, len(fields))}
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			w.allowed[f] = struct{}{}
		}
	}
	return w
}

// Allowed returns the set of accepted field names. Order is not guaranteed;
// intended for diagnostics and tests.
func (w *SortWhitelist) Allowed() []string {
	out := make([]string, 0, len(w.allowed))
	for f := range w.allowed {
		out = append(out, f)
	}
	return out
}

// Resolve parses a single sort expression and validates the field against the
// whitelist. Supported forms:
//
//	""            -> no sort requested (zero SortSpec, nil error)
//	"field"       -> ascending
//	"-field"      -> descending
//
// An unknown field, or an expression with no field name (e.g. "-"), is rejected
// with an error whose message is safe to return as a 400 detail.
func (w *SortWhitelist) Resolve(expr string) (SortSpec, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return SortSpec{}, nil
	}

	dir := SortAsc
	field := expr
	if strings.HasPrefix(expr, "-") {
		dir = SortDesc
		field = strings.TrimPrefix(expr, "-")
	}

	if field == "" {
		return SortSpec{}, fmt.Errorf("sort expression is missing a field name")
	}
	if _, ok := w.allowed[field]; !ok {
		return SortSpec{}, fmt.Errorf("sort field %q is not allowed", field)
	}

	return SortSpec{Field: field, Direction: dir}, nil
}
