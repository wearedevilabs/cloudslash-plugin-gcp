// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package manifest defines CloudSlash plugin manifest v2 (plugin.json).
//
// A manifest is a simple JSON file hosted in the plugin author's own GitHub
// repository (npm-style). Anyone can write one, point it at their release
// assets, and install it with CloudSlash — with or without the central
// registry. "type" is open-ended: a provider is just one kind of plugin.
package manifest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// semverPrefix normalizes a bare "2.1.0" to "v2.1.0" for x/mod/semver.
func semverPrefix(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// SchemaVersion is the current manifest schema version.
const SchemaVersion = 2

// Manifest is the parsed plugin.json (manifest v2).
type Manifest struct {
	SchemaVersion int      `json:"schema_version"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Type          string   `json:"type"` // open-ended: "provider", "heuristic", "policy-pack", ...
	Description   string   `json:"description,omitempty"`
	Author        *Person  `json:"author,omitempty"`
	Homepage      string   `json:"homepage,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	// CloudSlashMinVersion is the minimum core CLI version this plugin
	// supports. Installs refuse to proceed below it.
	CloudSlashMinVersion string `json:"cloudslash_min_version,omitempty"`
	// Source is the canonical repository, "github:owner/repo".
	Source string `json:"source,omitempty"`
	// Capabilities are free-form feature flags; known keys (discovery,
	// remediation, rightsize, pricing) drive core routing.
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	// CapabilityContracts describe where a capability may run and whether it
	// reads external systems or performs pure computation. The
	// map remains open-ended so new plugin capabilities require no SDK change.
	CapabilityContracts map[string]CapabilityContract `json:"capability_contracts,omitempty"`
	// Connections describes provider-neutral setup flows that a UI may render.
	// Cloud-specific field names and instructions belong to the plugin.
	Connections []ConnectionMethod `json:"connections,omitempty"`
	// Permissions declares requested actions per provider. These declarations
	// alone do not guarantee least privilege or a supported policy renderer.
	Permissions map[string]PermissionSet `json:"permissions,omitempty"`
	// PermissionDocuments contains provider-owned drafts covered by the manifest signature.
	PermissionDocuments []PermissionDocument `json:"permission_documents,omitempty"`
	// Entrypoints describes how the plugin runs, per type. Binary types
	// declare a command + protocol; policy packs declare rule files.
	Entrypoints *Entrypoints `json:"entrypoints,omitempty"`
	// Assets is the platform download matrix. At least one entry matching
	// the installer's platform is required for binary plugins.
	Assets []Asset `json:"assets,omitempty"`
	// PolicyProfiles are immutable informational profiles distributed with this
	// release. They are optional for source plugins and can stand alone in a
	// policy-pack. Installation never activates or authorizes their actions.
	PolicyProfiles []PolicyProfile `json:"policy_profiles,omitempty"`
	// Signature is an Ed25519 signature over the canonical manifest without this field.
	Signature string `json:"signature,omitempty"`
}

// CapabilityContract adds safety and execution metadata to a capability.
// Plugins may read external systems or perform pure computation. Mutation is
// deliberately absent from the plugin contract; local execution uses a
// separate executor-adapter boundary owned by the CLI/TUI.
type CapabilityContract struct {
	Version      string   `json:"version"`
	Effect       string   `json:"effect"`
	Environments []string `json:"environments"`
}

// ConnectionMethod is a plugin-defined way to authorize access to an
// external system. Flow names are generic UI primitives, never providers.
type ConnectionMethod struct {
	ID           string            `json:"id"`
	Label        string            `json:"label"`
	Description  string            `json:"description,omitempty"`
	Flow         string            `json:"flow"`
	Environments []string          `json:"environments"`
	Fields       []ConnectionField `json:"fields,omitempty"`
}

// ConnectionField describes one value collected by a connection form.
// Secret values must be write-only after submission. Generated values are
// created by Horizon or the local client and displayed read-only to the user.
type ConnectionField struct {
	Key         string             `json:"key"`
	Label       string             `json:"label"`
	Description string             `json:"description,omitempty"`
	Type        string             `json:"type"`
	Required    bool               `json:"required,omitempty"`
	Secret      bool               `json:"secret,omitempty"`
	Generated   bool               `json:"generated,omitempty"`
	Placeholder string             `json:"placeholder,omitempty"`
	Options     []ConnectionOption `json:"options,omitempty"`
}

type ConnectionOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Person identifies a plugin author.
type Person struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// PermissionSet retains Mutate only so validation can return a useful error
// for old documents. New plugin manifests may request read permissions only.
type PermissionSet struct {
	Read []string `json:"read,omitempty"`
	// Deprecated: plugin manifests cannot request mutation access.
	Mutate []string `json:"mutate,omitempty"`
}

// Entrypoints describes the runnable surface of a plugin.
type Entrypoints struct {
	// Binary is set for code plugins launched as go-plugin subprocesses.
	Binary *BinaryEntrypoint `json:"binary,omitempty"`
	// Hosted is an author-operated SaaS endpoint speaking cloudslash.remote.v1.Plugin.
	Hosted *HostedEntrypoint `json:"hosted,omitempty"`
	// Policies is a glob of CEL rule files for policy-pack plugins.
	Policies string `json:"policies,omitempty"`
}

type HostedEntrypoint struct {
	Endpoint string `json:"endpoint"`
	Protocol string `json:"protocol"`
}

// BinaryEntrypoint declares the gRPC plugin binary.
type BinaryEntrypoint struct {
	// Command is the binary name inside the extracted asset.
	Command string `json:"command"`
	// Protocol is the launch contract; the only value today is "grpc+goplugin".
	Protocol string `json:"protocol,omitempty"`
}

// Asset is one downloadable platform artifact.
type Asset struct {
	// Platform is "os/arch", e.g. "darwin/arm64", "linux/amd64".
	Platform string `json:"platform"`
	URL      string `json:"url"`
	// SHA256 is the hex digest of the downloaded archive. Required.
	SHA256 string `json:"sha256"`
	// SizeBytes is optional metadata for progress display.
	SizeBytes int64 `json:"size_bytes,omitempty"`
}

// Known entrypoint protocols.
const ProtocolGoPlugin = "grpc+goplugin"
const ProtocolHostedGRPC = "grpcs+cloudslash"

// Types that require a binary entrypoint and at least one asset.
var binaryTypes = map[string]bool{
	"provider":  true,
	"heuristic": true,
}

var nameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
var connectionKeyRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

var validCapabilityEffects = map[string]bool{"read": true, "compute": true}
var validEnvironments = map[string]bool{"local": true, "hosted": true}
var validConnectionFlows = map[string]bool{"form": true, "oauth2": true, "device-code": true, "outbound-agent": true}
var validConnectionFieldTypes = map[string]bool{
	"text": true, "secret": true, "url": true, "select": true,
	"multiselect": true, "boolean": true, "json": true, "file": true,
}

// Parse decodes and validates a plugin.json document.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: invalid JSON: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseFile reads and validates a plugin.json from disk.
// func ParseFile(path string) (*Manifest, error) { ... } is provided in io.go.

// Validate checks structural invariants. It is provider-agnostic: no cloud
// knowledge lives here.
func (m *Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("manifest: schema_version must be %d (got %d)", SchemaVersion, m.SchemaVersion)
	}
	if !ValidPackageName(m.Name) {
		return fmt.Errorf("manifest: invalid name %q (must match %s)", m.Name, nameRegex.String())
	}
	if m.Version == "" {
		return fmt.Errorf("manifest: version is required")
	}
	if !semver.IsValid(semverPrefix(m.Version)) {
		return fmt.Errorf("manifest: version %q must be semver (e.g. 2.1.0)", m.Version)
	}
	if m.Type == "" {
		return fmt.Errorf("manifest: type is required (e.g. \"provider\", \"policy-pack\" — open-ended)")
	}
	if m.Description == "" {
		return fmt.Errorf("manifest: description is required")
	}

	for name, contract := range m.CapabilityContracts {
		if !m.Capabilities[name] {
			return fmt.Errorf("manifest: capability contract %q requires an enabled capability", name)
		}
		if !semver.IsValid(semverPrefix(contract.Version)) {
			return fmt.Errorf("manifest: capability contract %q has invalid version %q", name, contract.Version)
		}
		if !validCapabilityEffects[contract.Effect] {
			return fmt.Errorf("manifest: capability contract %q has invalid effect %q", name, contract.Effect)
		}
		if err := validateEnvironments("capability contract "+name, contract.Environments); err != nil {
			return err
		}
	}
	for namespace, permissions := range m.Permissions {
		if len(permissions.Mutate) > 0 {
			return fmt.Errorf("manifest: plugin permissions for %q cannot declare mutation access", namespace)
		}
	}

	seenConnections := map[string]bool{}
	for _, connection := range m.Connections {
		if !connectionKeyRegex.MatchString(connection.ID) {
			return fmt.Errorf("manifest: invalid connection id %q", connection.ID)
		}
		if seenConnections[connection.ID] {
			return fmt.Errorf("manifest: duplicate connection id %q", connection.ID)
		}
		seenConnections[connection.ID] = true
		if strings.TrimSpace(connection.Label) == "" {
			return fmt.Errorf("manifest: connection %q requires a label", connection.ID)
		}
		if !validConnectionFlows[connection.Flow] {
			return fmt.Errorf("manifest: connection %q has invalid flow %q", connection.ID, connection.Flow)
		}
		if err := validateEnvironments("connection "+connection.ID, connection.Environments); err != nil {
			return err
		}
		if connection.Flow == "form" && len(connection.Fields) == 0 {
			return fmt.Errorf("manifest: form connection %q requires fields", connection.ID)
		}
		seenFields := map[string]bool{}
		for _, field := range connection.Fields {
			if !connectionKeyRegex.MatchString(field.Key) {
				return fmt.Errorf("manifest: connection %q has invalid field key %q", connection.ID, field.Key)
			}
			if seenFields[field.Key] {
				return fmt.Errorf("manifest: connection %q has duplicate field %q", connection.ID, field.Key)
			}
			seenFields[field.Key] = true
			if strings.TrimSpace(field.Label) == "" || !validConnectionFieldTypes[field.Type] {
				return fmt.Errorf("manifest: connection %q field %q has invalid label or type", connection.ID, field.Key)
			}
			if field.Secret && field.Type != "secret" && field.Type != "json" && field.Type != "file" {
				return fmt.Errorf("manifest: connection %q field %q marks a non-secret-capable type as secret", connection.ID, field.Key)
			}
			if (field.Type == "select" || field.Type == "multiselect") && len(field.Options) == 0 {
				return fmt.Errorf("manifest: connection %q field %q requires options", connection.ID, field.Key)
			}
		}
	}

	seenPlatforms := map[string]bool{}
	for _, a := range m.Assets {
		if a.Platform == "" || !strings.Contains(a.Platform, "/") {
			return fmt.Errorf("manifest: asset platform %q must be \"os/arch\"", a.Platform)
		}
		if a.URL == "" {
			return fmt.Errorf("manifest: asset %q has no url", a.Platform)
		}
		if a.SHA256 == "" {
			return fmt.Errorf("manifest: asset %q has no sha256 (integrity is mandatory)", a.Platform)
		}
		checksum, err := hex.DecodeString(a.SHA256)
		if err != nil || len(checksum) != 32 {
			return fmt.Errorf("manifest: asset %q has an invalid sha256 digest", a.Platform)
		}
		if seenPlatforms[a.Platform] {
			return fmt.Errorf("manifest: duplicate asset platform %q", a.Platform)
		}
		seenPlatforms[a.Platform] = true
	}

	if m.Entrypoints != nil && m.Entrypoints.Hosted != nil {
		hosted := m.Entrypoints.Hosted
		u, err := url.Parse(hosted.Endpoint)
		if err != nil || u.Scheme != "grpcs" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
			return fmt.Errorf("manifest: hosted endpoint must be a grpcs:// host on port 443")
		}
		if hosted.Protocol != ProtocolHostedGRPC {
			return fmt.Errorf("manifest: unsupported hosted protocol %q", hosted.Protocol)
		}
		active := false
		for _, enabled := range m.Capabilities {
			if enabled {
				active = true
				break
			}
		}
		if !active {
			return fmt.Errorf("manifest: hosted plugin must declare an active capability")
		}
	}

	if binaryTypes[m.Type] && (m.Entrypoints == nil || (m.Entrypoints.Binary == nil && m.Entrypoints.Hosted == nil)) {
		return fmt.Errorf("manifest: type %q requires entrypoints.binary or entrypoints.hosted", m.Type)
	}
	if m.Entrypoints != nil && m.Entrypoints.Binary != nil {
		if m.Entrypoints.Binary.Command == "" {
			return fmt.Errorf("manifest: entrypoints.binary.command is required")
		}
		command := m.Entrypoints.Binary.Command
		if command == "." || command == ".." || strings.ContainsAny(command, `/\`) {
			return fmt.Errorf("manifest: entrypoints.binary.command must be a file name")
		}
		if protocol := m.Entrypoints.Binary.Protocol; protocol != "" && protocol != ProtocolGoPlugin {
			return fmt.Errorf("manifest: unsupported binary protocol %q", protocol)
		}
		if len(m.Assets) == 0 {
			return fmt.Errorf("manifest: type %q requires at least one asset", m.Type)
		}
	}

	if m.Type == "policy-pack" {
		if len(m.PolicyProfiles) == 0 && (m.Entrypoints == nil || (m.Entrypoints.Policies == "" && m.Entrypoints.Hosted == nil)) {
			return fmt.Errorf("manifest: type %q requires entrypoints.policies or entrypoints.hosted", m.Type)
		}
	}
	if err := validatePermissionDocuments(m.PermissionDocuments); err != nil {
		return err
	}
	if err := validatePolicyProfiles(m.PolicyProfiles); err != nil {
		return err
	}
	return nil
}

func validateEnvironments(subject string, environments []string) error {
	if len(environments) == 0 {
		return fmt.Errorf("manifest: %s requires at least one environment", subject)
	}
	seen := map[string]bool{}
	for _, environment := range environments {
		if !validEnvironments[environment] {
			return fmt.Errorf("manifest: %s has invalid environment %q", subject, environment)
		}
		if seen[environment] {
			return fmt.Errorf("manifest: %s repeats environment %q", subject, environment)
		}
		seen[environment] = true
	}
	return nil
}

// AssetFor returns the asset matching an "os/arch" platform string.
func (m *Manifest) AssetFor(platform string) (*Asset, error) {
	for i := range m.Assets {
		if m.Assets[i].Platform == platform {
			return &m.Assets[i], nil
		}
	}
	available := make([]string, 0, len(m.Assets))
	for _, a := range m.Assets {
		available = append(available, a.Platform)
	}
	return nil, fmt.Errorf("manifest: no asset for platform %s (available: %v)", platform, available)
}

// IsBinaryType reports whether the plugin runs as a subprocess binary.
func (m *Manifest) IsBinaryType() bool {
	return m.Entrypoints != nil && m.Entrypoints.Binary != nil
}

// SigningBytes returns the existing SDK manifest signature wire format.
// Keep separate from CanonicalJSON: sorting through a generic map changes the
// bytes covered by signatures on already published manifests.
func (m *Manifest) SigningBytes() ([]byte, error) {
	unsigned := *m
	unsigned.Signature = ""
	return json.Marshal(&unsigned)
}

// CanonicalJSON re-serializes the manifest deterministically (sorted keys) so
// callers can compute a stable digest for pinning.
func (m *Manifest) CanonicalJSON() ([]byte, error) {
	// Round-trip through a generic map to drop formatting variance.
	var generic interface{}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}
