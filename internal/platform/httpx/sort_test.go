package httpx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gary-yang1/Dragon_asm/internal/platform/httpx"
)

func TestSortWhitelistResolve(t *testing.T) {
	w := httpx.NewSortWhitelist("created_at", "updated_at", "name")

	cases := []struct {
		name     string
		expr     string
		wantSpec httpx.SortSpec
		wantErr  bool
	}{
		{"empty yields no sort", "", httpx.SortSpec{}, false},
		{"whitespace only yields no sort", "   ", httpx.SortSpec{}, false},
		{"bare field is ascending", "name", httpx.SortSpec{Field: "name", Direction: httpx.SortAsc}, false},
		{"minus prefix is descending", "-created_at", httpx.SortSpec{Field: "created_at", Direction: httpx.SortDesc}, false},
		{"surrounding whitespace trimmed", "  name  ", httpx.SortSpec{Field: "name", Direction: httpx.SortAsc}, false},
		{"unknown field rejected", "owner", httpx.SortSpec{}, true},
		{"unknown desc field rejected", "-owner", httpx.SortSpec{}, true},
		{"lone minus rejected", "-", httpx.SortSpec{}, true},
		{"sql-injection-ish rejected", "created_at; DROP", httpx.SortSpec{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := w.Resolve(tc.expr)
			if tc.wantErr {
				require.Errorf(t, err, "expr=%q", tc.expr)
				assert.Equal(t, httpx.SortSpec{}, got, "no spec should be returned on error")
				return
			}
			require.NoErrorf(t, err, "expr=%q", tc.expr)
			assert.Equal(t, tc.wantSpec, got)
		})
	}
}

func TestSortWhitelistDedupAndAllowed(t *testing.T) {
	w := httpx.NewSortWhitelist("a", "a", "b", "  ", "")
	// Duplicates and blanks are dropped.
	assert.ElementsMatch(t, []string{"a", "b"}, w.Allowed())
}
