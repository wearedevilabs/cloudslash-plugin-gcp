// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package privacy rejects credential-shaped values at the public scan boundary.
// It is defense in depth; the plugin runtime must also keep secret leases out
// of its output and logs.
package privacy

import (
	"encoding/json"
	"errors"
	"strings"
)

var ErrSensitiveData = errors.New("public scan data contains a credential field")

var secretKeys = map[string]struct{}{
	"apikey": {}, "accesstoken": {}, "refreshtoken": {}, "sessiontoken": {},
	"secretaccesskey": {}, "clientsecret": {}, "privatekey": {},
	"password": {}, "passwd": {}, "credential": {}, "credentials": {},
	"authorization": {}, "bearertoken": {},
}

func normalizeKey(key string) string {
	key = strings.ToLower(key)
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			return -1
		}
		return r
	}, key)
}

func inspect(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if _, sensitive := secretKeys[normalizeKey(key)]; sensitive {
				return ErrSensitiveData
			}
			if err := inspect(nested); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := inspect(nested); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateJSON rejects nested credential field names without returning values
// or key names in the error. The caller should impose a byte limit first.
func ValidateJSON(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("invalid public JSON")
	}
	return inspect(value)
}

// ValidateText blocks common accidental credential dumps in diagnostics.
func ValidateText(value string) error {
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization:", "bearer ", "api_key=", "apikey=", "password=", "secret=", "client_secret="} {
		if strings.Contains(lower, marker) {
			return ErrSensitiveData
		}
	}
	return nil
}
