package auth

import (
	"sort"
	"strconv"
)

// actorID renders a numeric user id as the string used in JWT subjects, Casbin
// subjects, and audit actor ids, keeping one canonical representation.
func actorID(id uint64) string { return strconv.FormatUint(id, 10) }

// parseUserID converts a subject string back to the numeric user id. A
// non-numeric or empty subject is an error (a forged or foreign token).
func parseUserID(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// sortStrings sorts in place; isolated here so the service reads declaratively.
func sortStrings(ss []string) { sort.Strings(ss) }
