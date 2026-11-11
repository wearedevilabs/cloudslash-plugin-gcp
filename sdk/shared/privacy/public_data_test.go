package privacy

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestRejectNestedCredentialFieldsAndDiagnostics(t *testing.T) {
	for _, raw := range []string{
		`{"api_key":"secret"}`, `{"items":[{"client-secret":"secret"}]}`,
		`{"nested":{"private_key":"secret"}}`,
	} {
		if err := ValidateJSON(json.RawMessage(raw)); !errors.Is(err, ErrSensitiveData) {
			t.Fatalf("sensitive field accepted: %s", raw)
		}
	}
	if err := ValidateJSON(json.RawMessage(`{"secret_name":"identifier","state":"idle"}`)); err != nil {
		t.Fatalf("safe metadata rejected: %v", err)
	}
	if err := ValidateText("Authorization: Bearer abc"); !errors.Is(err, ErrSensitiveData) {
		t.Fatalf("credential diagnostic accepted: %v", err)
	}
}
