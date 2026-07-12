package baiyan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	quakeAPIBaseURL  = "https://quake.360.net"
	quakeUserInfoURL = quakeAPIBaseURL + "/api/v3/user/info"
	quakeSearchURL   = quakeAPIBaseURL + "/api/v3/search/quake_service"
)

type quakeCode string

type quakeEnvelope struct {
	Code    quakeCode       `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (c *quakeCode) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*c = ""
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*c = quakeCode(strings.TrimSpace(text))
		return nil
	}

	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		*c = quakeCode(number.String())
		return nil
	}

	return fmt.Errorf("解析 Quake code 失败: %s", string(data))
}

func (c quakeCode) IsSuccess() bool {
	switch strings.TrimSpace(strings.ToLower(string(c))) {
	case "0", "200":
		return true
	default:
		return false
	}
}

func (c quakeCode) String() string {
	return string(c)
}

func quakeDataEmpty(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || bytes.Equal(raw, []byte("null"))
}

func decodeQuakeRows(raw json.RawMessage) ([]map[string]interface{}, error) {
	if quakeDataEmpty(raw) {
		return nil, nil
	}

	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("解析 Quake data 失败: %w", err)
	}
	return rows, nil
}
