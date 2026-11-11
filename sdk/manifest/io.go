// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package manifest

import (
	"fmt"
	"os"
)

// ParseFile reads and validates a plugin.json from disk.
func ParseFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return Parse(data)
}

// WriteFile serializes the manifest to disk as pretty JSON.
func WriteFile(path string, m *Manifest) error {
	data, err := jsonMarshalIndent(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
