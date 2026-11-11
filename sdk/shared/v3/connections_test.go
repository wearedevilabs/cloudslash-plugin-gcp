package v3

import (
	"fmt"
	"testing"
)

// The contract must not cap how much a plugin can see. AWS declares dozens of
// read actions today; a wider provider may declare hundreds. Only individual
// entries and the request body are bounded.
func TestConnectionMethodAcceptsLargePermissionSets(t *testing.T) {
	permissions := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		permissions = append(permissions, fmt.Sprintf("provider%d:ListResources", i))
	}
	method := ConnectionMethod{
		ID:           "api-key",
		Title:        "API key",
		Instructions: "Create a read-only key.",
		Permissions:  permissions,
		ReadOnly:     true,
		Fields:       []ConnectionField{{Key: "api_key", Label: "API key", Type: "secret", MaxLength: 512}},
	}
	if err := method.Validate(); err != nil {
		t.Fatalf("a 600-permission method must validate, got %v", err)
	}
}
