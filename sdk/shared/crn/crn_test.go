package crn

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fixture struct {
	Valid []struct {
		Raw, Source, Scope, Service, Type, Account, ID string
	}
	Invalid []string
}

func TestV2Conformance(t *testing.T) {
	data, err := os.ReadFile("testdata/v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases fixture
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, want := range cases.Valid {
		got, err := Parse(want.Raw)
		if err != nil {
			t.Errorf("parse %q: %v", want.Raw, err)
			continue
		}
		if got.SourceName() != want.Source || got.Scope() != want.Scope ||
			got.Service != want.Service || got.Type != want.Type ||
			got.Account != want.Account || got.ID != want.ID ||
			got.String() != want.Raw || got.Provider != want.Source {
			t.Errorf("round trip %q: %+v", want.Raw, got)
		}
		constructed, err := NewChecked(want.Source, want.Scope, want.Service, want.Type, want.Account, want.ID)
		if err != nil || constructed.String() != want.Raw {
			t.Errorf("construct %q: %v, %q", want.Raw, err, constructed.String())
		}
	}
	for _, raw := range cases.Invalid {
		if _, err := Parse(raw); err == nil {
			t.Errorf("accepted invalid CRN %q", raw)
		}
	}
}

func TestLengthAndLegacyProvider(t *testing.T) {
	c := CRN{Provider: "unknown-source", Service: "svc", Type: "kind", ID: "x"}
	if c.SourceName() != "unknown-source" {
		t.Fatal("legacy provider field was lost")
	}
	if _, err := Parse(c.String()); err != nil {
		t.Fatal(err)
	}
	parsed, _ := Parse(c.String())
	if parsed != c {
		t.Fatalf("parsed CRN must equal legacy map key: %#v != %#v", parsed, c)
	}
	c.ID = strings.Repeat("x", MaxLength)
	if !errors.Is(c.Validate(), ErrTooLong) {
		t.Fatal("oversized CRN accepted")
	}
	if _, err := Parse(c.String()); !errors.Is(err, ErrTooLong) {
		t.Fatal("oversized serialization accepted")
	}
}

func TestAuditDoesNotRewrite(t *testing.T) {
	raw := []string{"crn:devi:lab::svc:kind::ok", "crn:devi:lab::svc:kind::bad:id"}
	report := AuditStoredNames(raw)
	if len(report) != 1 || report[0].Raw != raw[1] || raw[1] != "crn:devi:lab::svc:kind::bad:id" {
		t.Fatalf("unexpected migration report: %+v", report)
	}
}
