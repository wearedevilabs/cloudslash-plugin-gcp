// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package v3 is the read/compute/egress plugin contract. It intentionally
// contains no infrastructure mutation or executor operation.
package v3

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const ProtocolVersion = 3

type Role string

const (
	Source                 Role = "source"
	Enricher               Role = "enricher"
	Analyzer               Role = "analyzer"
	PolicyPack             Role = "policy-pack"
	PricingCatalog         Role = "pricing-catalog"
	CostImporter           Role = "cost-importer"
	TelemetryImporter      Role = "telemetry-importer"
	ServiceCatalogImporter Role = "service-catalog-importer"
	Exporter               Role = "exporter"
	NotificationSink       Role = "notification-sink"
)

type Effect string

const (
	Read    Effect = "read"
	Compute Effect = "compute"
	Egress  Effect = "egress"
)

type Environment string

const (
	Local          Environment = "local"
	Hosted         Environment = "hosted"
	CustomerRunner Environment = "customer-runner"
)

// Limits are per job, not hints. A zero limit is invalid for a runnable
// capability and must not be replaced by an unbounded default.
type Limits struct {
	MaxBatchBytes  int64 `json:"max_batch_bytes"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
	MaxResources   int64 `json:"max_resources"`
	MaxDurationMS  int64 `json:"max_duration_ms"`
	MaxConcurrency int   `json:"max_concurrency"`
}

type Capability struct {
	Name                 string        `json:"name"`
	Version              string        `json:"version"`
	Role                 Role          `json:"role"`
	Effect               Effect        `json:"effect"`
	Environments         []Environment `json:"environments"`
	InputSchema          string        `json:"input_schema"`
	OutputSchema         string        `json:"output_schema"`
	ConnectionMethodIDs  []string      `json:"connection_method_ids,omitempty"`
	ReadDataClasses      []string      `json:"read_data_classes,omitempty"`
	OutputDataClasses    []string      `json:"output_data_classes,omitempty"`
	EgressDestinations   []string      `json:"egress_destinations,omitempty"`
	Limits               Limits        `json:"limits"`
	Deterministic        bool          `json:"deterministic"`
	SupportsCancellation bool          `json:"supports_cancellation"`
	SupportsPartial      bool          `json:"supports_partial"`
}

var supportedSchemas = map[string]struct{}{
	"scan.request/v1": {}, "scan.batch/v1": {},
	"snapshot/v1": {}, "signal/v1": {}, "policy/v1": {},
	"price/v1": {}, "cost/v1": {}, "telemetry/v1": {},
	"catalog/v1": {}, "query/v1": {}, "artifact/v1": {},
	"event/v1": {}, "receipt/v1": {},
}

func (c Capability) Validate() error {
	if c.Name == "" || strings.TrimSpace(c.Name) != c.Name || c.Version == "" {
		return errors.New("v3: capability requires a stable name and version")
	}
	if _, ok := supportedSchemas[c.InputSchema]; !ok {
		return fmt.Errorf("v3: unsupported input schema %q", c.InputSchema)
	}
	if _, ok := supportedSchemas[c.OutputSchema]; !ok {
		return fmt.Errorf("v3: unsupported output schema %q", c.OutputSchema)
	}
	if c.Limits.MaxBatchBytes <= 0 || c.Limits.MaxOutputBytes <= 0 ||
		c.Limits.MaxResources <= 0 || c.Limits.MaxDurationMS <= 0 ||
		c.Limits.MaxDurationMS > math.MaxInt64/int64(time.Millisecond) ||
		c.Limits.MaxConcurrency <= 0 ||
		c.Limits.MaxBatchBytes > c.Limits.MaxOutputBytes {
		return errors.New("v3: capability requires finite, consistent resource limits")
	}
	if !c.SupportsCancellation {
		return errors.New("v3: cancellation support is required")
	}
	allowed := map[Role][]Effect{
		Source: {Read}, Enricher: {Read, Compute},
		Analyzer: {Compute}, PolicyPack: {Compute},
		PricingCatalog: {Read, Compute}, CostImporter: {Read},
		TelemetryImporter: {Read}, ServiceCatalogImporter: {Read},
		Exporter: {Egress}, NotificationSink: {Egress},
	}
	effects, ok := allowed[c.Role]
	if !ok {
		return fmt.Errorf("v3: unsupported role %q", c.Role)
	}
	validEffect := false
	for _, effect := range effects {
		if c.Effect == effect {
			validEffect = true
		}
	}
	if !validEffect {
		return fmt.Errorf("v3: role %q cannot declare effect %q", c.Role, c.Effect)
	}
	if c.Effect == Egress && len(c.EgressDestinations) == 0 {
		return errors.New("v3: egress requires declared destinations")
	}
	if c.Effect != Egress && len(c.EgressDestinations) > 0 {
		return errors.New("v3: undeclared egress effect")
	}
	if len(c.Environments) == 0 {
		return errors.New("v3: no environments declared")
	}
	seen := make(map[Environment]struct{}, len(c.Environments))
	for _, env := range c.Environments {
		if env != Local && env != Hosted && env != CustomerRunner {
			return fmt.Errorf("v3: unsupported environment %q", env)
		}
		if _, duplicate := seen[env]; duplicate {
			return fmt.Errorf("v3: duplicate environment %q", env)
		}
		seen[env] = struct{}{}
	}
	for _, method := range c.ConnectionMethodIDs {
		if method == "" {
			return errors.New("v3: empty connection method")
		}
	}
	for _, destination := range c.EgressDestinations {
		if destination == "" {
			return errors.New("v3: empty egress destination")
		}
	}
	return nil
}

// AvailableIn fails closed on invalid declarations. Hosted callers must never
// translate a v2 remediation capability into a hosted v3 capability.
func (c Capability) AvailableIn(env Environment) bool {
	if c.Validate() != nil {
		return false
	}
	for _, declared := range c.Environments {
		if declared == env {
			return true
		}
	}
	return false
}

// SecretLease is a scoped reference; it never carries raw credentials.
type SecretLease struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	InstallationID string    `json:"installation_id"`
	CapabilityName string    `json:"capability_name"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (l SecretLease) Validate(now time.Time, organizationID, installationID, capabilityName string) error {
	if l.ID == "" || l.OrganizationID != organizationID ||
		l.InstallationID != installationID || l.CapabilityName != capabilityName ||
		!now.Before(l.ExpiresAt) {
		return errors.New("v3: invalid or expired scoped lease")
	}
	return nil
}

type PreflightResult struct {
	DisplayName        string    `json:"display_name"`
	ObservedScopes     []string  `json:"observed_scopes"`
	MissingScopes      []string  `json:"missing_scopes"`
	ReachableScopes    []string  `json:"reachable_scopes"`
	CapabilityVersions []string  `json:"capability_versions"`
	ExpiresAt          time.Time `json:"expires_at,omitempty"`
	RotationHint       string    `json:"rotation_hint,omitempty"`
	RedactedWarnings   []string  `json:"redacted_warnings,omitempty"`
}
