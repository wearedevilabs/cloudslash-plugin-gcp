// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package manifest

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// V1 is the legacy manifest.yaml structure (kept for one release so existing
// plugins and installs keep working; converted on read).
type V1 struct {
	Name             string                   `yaml:"name"     json:"name"`
	Version          string                   `yaml:"version"  json:"version"`
	Type             string                   `yaml:"type"     json:"type"`
	Author           string                   `yaml:"author"   json:"author"`
	Description      string                   `yaml:"description" json:"description"`
	Tags             []string                 `yaml:"tags"     json:"tags"`
	CloudSlashMinVer string                   `yaml:"cloudslash_min_version" json:"cloudslash_min_version"`
	Binaries         map[string]string        `yaml:"binaries"  json:"binaries"`
	Checksums        map[string]string        `yaml:"checksums" json:"checksums"`
	Signature        string                   `yaml:"signature"  json:"signature"`
	Permissions      map[string]PermissionSet `yaml:"permissions" json:"permissions"`
	Platforms        map[string]string        `yaml:"platforms"  json:"platforms"`
	Capabilities     map[string]interface{}   `yaml:"capabilities" json:"capabilities"`
}

// ParseV1YAML parses a legacy manifest.yaml document.
func ParseV1YAML(data []byte) (*V1, error) {
	var v1 V1
	if err := yaml.Unmarshal(data, &v1); err != nil {
		return nil, fmt.Errorf("manifest: invalid v1 YAML: %w", err)
	}
	return &v1, nil
}

// ConvertV1 upgrades a legacy manifest to manifest v2. Binaries/Platforms and
// Checksums are merged into the assets matrix; checksums are mandatory in v2,
// so binaries without checksums are dropped with a note in the error return
// (the manifest is still returned for partial use).
func ConvertV1(v1 *V1) (*Manifest, error) {
	caps := map[string]bool{}
	for k, v := range v1.Capabilities {
		if b, ok := v.(bool); ok {
			caps[k] = b
		}
	}

	m := &Manifest{
		SchemaVersion:        SchemaVersion,
		Name:                 v1.Name,
		Version:              v1.Version,
		Type:                 v1.Type,
		Description:          v1.Description,
		Author:               &Person{Name: v1.Author},
		Tags:                 v1.Tags,
		CloudSlashMinVersion: v1.CloudSlashMinVer,
		Capabilities:         caps,
		Permissions:          v1.Permissions,
	}

	urls := map[string]string{}
	for platform, url := range v1.Binaries {
		urls[platform] = url
	}
	for platform, url := range v1.Platforms {
		urls[platform] = url
	}

	var dropped []string
	for platform, url := range urls {
		sha := v1.Checksums[platform]
		if sha == "" {
			dropped = append(dropped, platform)
			continue
		}
		m.Assets = append(m.Assets, Asset{Platform: platform, URL: url, SHA256: sha})
	}

	if len(m.Assets) > 0 && m.Entrypoints == nil {
		m.Entrypoints = &Entrypoints{
			Binary: &BinaryEntrypoint{
				Command:  "cloudslash-plugin-" + m.Name,
				Protocol: ProtocolGoPlugin,
			},
		}
	}

	var err error
	if len(dropped) > 0 {
		err = fmt.Errorf("manifest: v1 assets without checksums dropped: %v", dropped)
	}
	return m, err
}
