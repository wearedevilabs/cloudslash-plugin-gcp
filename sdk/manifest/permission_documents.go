// SPDX-License-Identifier: Apache-2.0
package manifest

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxPermissionDocuments = 32
const MaxPermissionDocumentBytes = 256 << 10
const MaxPermissionDocumentsBytes = 1 << 20

// PermissionDocument is an opaque, static permission draft. The host exports
// exact content; it never interpolates, executes, merges, or applies it. Provider
// and format are plugin-defined identifiers, not core provider enumerations.
type PermissionDocument struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Format   string `json:"format"`
	Content  string `json:"content"`
}

func validatePermissionDocuments(documents []PermissionDocument) error {
	if len(documents) > MaxPermissionDocuments {
		return fmt.Errorf("manifest: too many permission documents")
	}
	seen := map[string]bool{}
	total := 0
	for _, d := range documents {
		if !ValidPackageName(d.ID) || seen[d.ID] {
			return fmt.Errorf("manifest: invalid or duplicate permission document id %q", d.ID)
		}
		seen[d.ID] = true
		if !ValidPackageName(d.Provider) || !ValidPackageName(d.Format) {
			return fmt.Errorf("manifest: permission document %q requires provider and format identifiers", d.ID)
		}
		total += len(d.Content)
		if strings.TrimSpace(d.Content) == "" || len(d.Content) > MaxPermissionDocumentBytes || total > MaxPermissionDocumentsBytes || !utf8.ValidString(d.Content) {
			return fmt.Errorf("manifest: invalid or oversized permission document %q", d.ID)
		}
		for _, c := range d.Content {
			if (unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t') || unicode.Is(unicode.Cf, c) {
				return fmt.Errorf("manifest: permission document %q contains unsafe control characters", d.ID)
			}
		}
	}
	return nil
}
