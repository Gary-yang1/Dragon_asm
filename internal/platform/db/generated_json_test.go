package db_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	dbgen "github.com/Gary-yang1/Dragon_asm/internal/platform/db/generated"
)

// Guards a whole class of outage rather than one column.
//
// sqlc maps a MySQL JSON column to json.RawMessage by default, and database/sql
// cannot scan NULL into that named slice type — it fails with "unsupported Scan,
// storing driver.Value type <nil>". Because the generated queries are SELECT *,
// one NULL in one nullable JSON column took down the entire list endpoint: a port
// exposure with no certificate SANs broke the exposure page, an unscored risk
// broke the risk page.
//
// The sqlc.yaml override maps JSON columns to []byte, which database/sql handles
// natively. This test fails if that override is ever dropped or a new model
// reintroduces json.RawMessage.
func TestGeneratedModelsUseByteSliceForJSONColumns(t *testing.T) {
	rawMessageType := reflect.TypeOf(json.RawMessage(nil))

	models := []any{
		dbgen.Risk{},
		dbgen.RiskScoreHistory{},
		dbgen.Exposure{},
		dbgen.ChangeEvent{},
		dbgen.ChangeEventArchive{},
		dbgen.NotificationRule{},
		dbgen.NotificationDelivery{},
		dbgen.DiscoveryCallback{},
		dbgen.DiscoveryObservation{},
		dbgen.ReportExport{},
		dbgen.TaskTemplate{},
	}

	for _, model := range models {
		typ := reflect.TypeOf(model)
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.Type == rawMessageType {
					t.Errorf("%s.%s is json.RawMessage; database/sql cannot scan NULL into it. "+
						"Keep the JSON override in sqlc.yaml so it stays []byte.", typ.Name(), field.Name)
				}
			}
		})
	}
}

// The scan behaviour the override buys us, asserted against database/sql's real
// conversion path so the reason for the override stays documented and checkable.
func TestByteSliceScansNullButRawMessageDoesNot(t *testing.T) {
	t.Run("json.RawMessage rejects NULL", func(t *testing.T) {
		var raw json.RawMessage
		err := scanNullInto(t, &raw)
		if err == nil {
			t.Fatal("json.RawMessage accepted a NULL scan; if database/sql changed, " +
				"re-evaluate whether the sqlc override is still required")
		}
	})

	t.Run("[]byte accepts NULL as nil", func(t *testing.T) {
		var b []byte
		if err := scanNullInto(t, &b); err != nil {
			t.Fatalf("[]byte must accept a NULL scan: %v", err)
		}
		if b != nil {
			t.Fatalf("NULL must scan as nil, got %v", b)
		}
	})
}

// scanNullInto pushes a single SQL NULL through database/sql into dest.
func scanNullInto(t *testing.T, dest any) error {
	t.Helper()
	conn, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = conn.Close() }()

	mock.ExpectQuery("SELECT j").WillReturnRows(sqlmock.NewRows([]string{"j"}).AddRow(nil))
	rows, err := conn.Query("SELECT j")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		t.Fatal("expected one row")
	}
	return rows.Scan(dest)
}
