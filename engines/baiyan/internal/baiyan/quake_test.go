package baiyan

import (
	"encoding/json"
	"testing"
)

func TestQuakeEnvelopeSupportsNumericAndStringCodes(t *testing.T) {
	t.Run("success numeric code", func(t *testing.T) {
		var env quakeEnvelope
		payload := []byte(`{"code":0,"message":"Successful.","data":[{"domain":"example.com"}]}`)
		if err := json.Unmarshal(payload, &env); err != nil {
			t.Fatalf("unmarshal quake envelope: %v", err)
		}
		if !env.Code.IsSuccess() {
			t.Fatalf("expected success code, got %q", env.Code.String())
		}

		rows, err := decodeQuakeRows(env.Data)
		if err != nil {
			t.Fatalf("decode quake rows: %v", err)
		}
		if len(rows) != 1 || rows[0]["domain"] != "example.com" {
			t.Fatalf("unexpected rows: %#v", rows)
		}
	})

	t.Run("error string code", func(t *testing.T) {
		var env quakeEnvelope
		payload := []byte(`{"code":"q2001","message":"用户当前积分不足以完成本次查询操作。","data":{}}`)
		if err := json.Unmarshal(payload, &env); err != nil {
			t.Fatalf("unmarshal quake envelope: %v", err)
		}
		if env.Code.IsSuccess() {
			t.Fatalf("expected non-success code, got %q", env.Code.String())
		}
		if env.Code.String() != "q2001" {
			t.Fatalf("unexpected code: %q", env.Code.String())
		}
	})
}
