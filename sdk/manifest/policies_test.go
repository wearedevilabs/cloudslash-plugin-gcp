package manifest

import (
	"strings"
	"testing"
)

func TestPolicyProfilesContract(t *testing.T) {
	valid := PolicyProfile{ID: "idle-energy", Version: "1.0.0", Schema: InformationalProfileSchema, URL: "https://example.org/release/policy.json", SHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name   string
		mutate func(*PolicyProfile)
	}{
		{"path", func(p *PolicyProfile) { p.ID = "../escape" }},
		{"unbounded-name", func(p *PolicyProfile) { p.ID = strings.Repeat("a", 65) }},
		{"http", func(p *PolicyProfile) { p.URL = "http://example.org/policy" }},
		{"credentials", func(p *PolicyProfile) { p.URL = "https://user:secret@example.org/policy" }},
		{"schema", func(p *PolicyProfile) { p.Schema = "unknown" }},
		{"checksum", func(p *PolicyProfile) { p.SHA256 = "abc" }},
		{"version", func(p *PolicyProfile) { p.Version = "latest" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.mutate(&p)
			if err := validatePolicyProfiles([]PolicyProfile{p}); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	if err := validatePolicyProfiles([]PolicyProfile{valid}); err != nil {
		t.Fatal(err)
	}
	if err := validatePolicyProfiles([]PolicyProfile{valid, valid}); err == nil {
		t.Fatal("duplicate accepted")
	}
}
