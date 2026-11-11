package manifest

import (
	"bytes"
	"strings"
	"testing"
)

func TestPermissionDocumentValidationAndSigning(t *testing.T) {
	good := PermissionDocument{ID: "reader", Provider: "custom-system", Format: "terraform", Content: "${literal}\n"}
	if err := validatePermissionDocuments([]PermissionDocument{good}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*PermissionDocument)
	}{
		{"path", func(d *PermissionDocument) { d.ID = "../reader" }},
		{"provider", func(d *PermissionDocument) { d.Provider = "" }},
		{"format", func(d *PermissionDocument) { d.Format = "../../json" }},
		{"empty", func(d *PermissionDocument) { d.Content = " \n" }},
		{"terminal-escape", func(d *PermissionDocument) { d.Content = "\x1b[2J" }},
		{"bidi", func(d *PermissionDocument) { d.Content = "\u202eevil" }},
		{"oversized", func(d *PermissionDocument) { d.Content = strings.Repeat("a", MaxPermissionDocumentBytes+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := good
			tc.change(&d)
			if validatePermissionDocuments([]PermissionDocument{d}) == nil {
				t.Fatal("accepted invalid document")
			}
		})
	}
	if validatePermissionDocuments([]PermissionDocument{good, good}) == nil {
		t.Fatal("accepted duplicate")
	}
	docs := make([]PermissionDocument, 5)
	for i := range docs {
		docs[i] = good
		docs[i].ID = string(rune('a' + i))
		docs[i].Content = strings.Repeat("a", MaxPermissionDocumentBytes)
	}
	if validatePermissionDocuments(docs) == nil {
		t.Fatal("accepted oversized aggregate")
	}
	m := &Manifest{PermissionDocuments: []PermissionDocument{good}}
	before, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	m.PermissionDocuments[0].Content = "changed"
	after, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("document is not covered by signing bytes")
	}
}
