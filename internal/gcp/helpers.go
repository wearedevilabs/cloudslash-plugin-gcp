package gcp

import (
	"encoding/json"
	"strings"
)

func encode(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func crn(parts ...string) string {
	return "gcp://" + strings.Join(parts, "/")
}

func regionFromZone(zone string) string {
	if index := strings.LastIndex(zone, "-"); index > 0 {
		return zone[:index]
	}
	return zone
}
