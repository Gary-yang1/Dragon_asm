package audit

import (
	"reflect"
	"strings"
)

// exactSensitiveKeys covers keys that must match exactly (case-insensitive) to
// avoid false positives on common field names.
var exactSensitiveKeys = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"set-cookie":    true,
}

// sensitiveSubstrings lists normalized substrings; a key whose normalized form
// contains any of these is redacted. Normalization strips hyphens and underscores
// and lowercases, so "access_token", "AccessToken", "REFRESH-TOKEN", "apiKey",
// "API_KEY" etc. all match.
var sensitiveSubstrings = []string{"token", "password", "secret", "apikey"}

const redactedPlaceholder = "[REDACTED]"

// normalizeKey lowercases k and removes hyphens and underscores so that
// access_token, AccessToken, REFRESH-TOKEN all normalize to the same form.
func normalizeKey(k string) string {
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, "-", "")
	return k
}

// isSensitiveKey reports whether a map/struct key should be redacted.
func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	if exactSensitiveKeys[lower] {
		return true
	}
	norm := normalizeKey(k)
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(norm, sub) {
			return true
		}
	}
	return false
}

// Redact returns a deep copy of v with the values of sensitive keys replaced by
// "[REDACTED]". Key matching is case-insensitive and covers common variants such
// as access_token, refresh_token, apiKey, API_KEY. Handles map[string]any,
// map[string]string, arbitrary maps with string keys, slices, arrays, and
// structs (converted to map[string]any using json tags or field names).
// Primitives and other unsupported types are returned as-is.
func Redact(v any) any {
	if v == nil {
		return nil
	}
	return redactValue(reflect.ValueOf(v))
}

func redactValue(rv reflect.Value) any {
	// Unwrap interface and pointer indirections.
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Map:
		return redactMap(rv)
	case reflect.Slice, reflect.Array:
		return redactSlice(rv)
	case reflect.Struct:
		return redactStruct(rv)
	default:
		return rv.Interface()
	}
}

// redactMap handles any map whose key kind is string.
func redactMap(rv reflect.Value) any {
	if rv.IsNil() {
		return nil
	}
	out := make(map[string]any, rv.Len())
	for _, key := range rv.MapKeys() {
		k := key.String()
		child := rv.MapIndex(key)
		if isSensitiveKey(k) {
			out[k] = redactedPlaceholder
		} else {
			out[k] = redactValue(child)
		}
	}
	return out
}

// redactSlice handles slices and arrays of any element type.
func redactSlice(rv reflect.Value) any {
	n := rv.Len()
	out := make([]any, n)
	for i := range n {
		out[i] = redactValue(rv.Index(i))
	}
	return out
}

// redactStruct converts a struct to map[string]any using json tags (falling
// back to field names) and redacts sensitive keys.
func redactStruct(rv reflect.Value) any {
	rt := rv.Type()
	out := make(map[string]any, rt.NumField())
	for i := range rt.NumField() {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		key := fieldKey(f)
		if key == "-" {
			continue
		}
		if isSensitiveKey(key) {
			out[key] = redactedPlaceholder
		} else {
			out[key] = redactValue(rv.Field(i))
		}
	}
	return out
}

// fieldKey returns the JSON key for a struct field: the first json tag segment
// if present, otherwise the field name.
func fieldKey(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}
