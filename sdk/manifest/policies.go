// SPDX-License-Identifier: Apache-2.0
package manifest

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path"

	"golang.org/x/mod/semver"
)

const InformationalProfileSchema = "cloudslash.analysis-profile/v1"
const MaxPolicyProfileBytes = 1 << 20
const MaxPolicyProfiles = 32

// PolicyProfile binds policy content to the plugin release's signed manifest.
// URL is an immutable release artifact, not a repository glob. SHA256 covers
// exact downloaded bytes; ID and Version must also match the decoded profile.
type PolicyProfile struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Schema  string `json:"schema"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// ValidPackageName is shared by install, lookup and removal boundaries.
func ValidPackageName(name string) bool {
	return len(name) <= 64 && nameRegex.MatchString(name)
}

func (p PolicyProfile) RelativePath() string { return path.Join("policies", p.ID+".json") }

func validatePolicyProfiles(profiles []PolicyProfile) error {
	if len(profiles) > MaxPolicyProfiles {
		return fmt.Errorf("manifest: at most %d policy profiles are allowed", MaxPolicyProfiles)
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		if !ValidPackageName(p.ID) || seen[p.ID] {
			return fmt.Errorf("manifest: invalid or duplicate policy profile id %q", p.ID)
		}
		seen[p.ID] = true
		if !semver.IsValid(semverPrefix(p.Version)) {
			return fmt.Errorf("manifest: policy profile %q requires a semantic version", p.ID)
		}
		if p.Schema != InformationalProfileSchema {
			return fmt.Errorf("manifest: unsupported policy profile schema %q", p.Schema)
		}
		digest, err := hex.DecodeString(p.SHA256)
		if err != nil || len(digest) != 32 {
			return fmt.Errorf("manifest: policy profile %q requires a SHA-256 digest", p.ID)
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("manifest: policy profile %q requires an HTTPS artifact URL", p.ID)
		}
	}
	return nil
}
