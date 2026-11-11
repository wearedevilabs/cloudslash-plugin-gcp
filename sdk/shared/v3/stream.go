// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package v3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/crn"
	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/privacy"
)

type ResultState string

const (
	ResultComplete ResultState = "complete"
	ResultPartial  ResultState = "partial"
	ResultFailed   ResultState = "failed"
)

type Envelope struct {
	ProtocolVersion   int       `json:"protocol_version"`
	JobID             string    `json:"job_id"`
	OrganizationNonce string    `json:"organization_nonce"`
	PluginDigest      string    `json:"plugin_digest"`
	CapabilityName    string    `json:"capability_name"`
	CapabilityVersion string    `json:"capability_version"`
	InputDigest       string    `json:"input_digest"`
	Sequence          uint64    `json:"sequence"`
	ObservedAt        time.Time `json:"observed_at"`
	TraceID           string    `json:"trace_id"`
}

// Signal is plugin evidence, never a CloudSlash finding.
type Signal struct {
	CRN         string          `json:"crn"`
	Kind        string          `json:"kind"`
	Observation json.RawMessage `json:"observation"`
	EvidenceIDs []string        `json:"evidence_ids"`
}

type Resource struct {
	CRN         string          `json:"crn"`
	Properties  json.RawMessage `json:"properties,omitempty"`
	EvidenceIDs []string        `json:"evidence_ids,omitempty"`
}

type Evidence struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Observation json.RawMessage `json:"observation,omitempty"`
}

type Relationship struct {
	SourceCRN string `json:"source_crn"`
	TargetCRN string `json:"target_crn"`
	Kind      string `json:"kind"`
}

type Batch struct {
	Envelope      Envelope       `json:"envelope"`
	Resources     []Resource     `json:"resources,omitempty"`
	Relationships []Relationship `json:"relationships,omitempty"`
	Evidence      []Evidence     `json:"evidence,omitempty"`
	Signals       []Signal       `json:"signals,omitempty"`
	Coverage      []string       `json:"coverage,omitempty"`
	Diagnostics   []string       `json:"diagnostics,omitempty"`
	Final         bool           `json:"final"`
	State         ResultState    `json:"state,omitempty"`
}

// StreamValidator is a synchronous, bounded consumer. Backpressure follows
// from accepting the next batch only after Receive has validated the last.
type StreamValidator struct {
	capability Capability
	expected   Envelope
	next       uint64
	bytes      int64
	resources  int64
	nodes      map[string]struct{}
	evidence   map[string]struct{}
	references []string
	edges      []Relationship
	signals    []string
	seen       map[uint64]string
	finished   bool
	started    time.Time
}

func NewStreamValidator(capability Capability, expected Envelope, now time.Time) (*StreamValidator, error) {
	if err := capability.Validate(); err != nil {
		return nil, err
	}
	if capability.Role != Source || capability.Effect != Read ||
		capability.OutputSchema != "scan.batch/v1" {
		return nil, errors.New("v3: source stream requires a read scan.batch/v1 capability")
	}
	if expected.ProtocolVersion != ProtocolVersion || expected.JobID == "" ||
		expected.OrganizationNonce == "" || expected.PluginDigest == "" ||
		expected.CapabilityName != capability.Name ||
		expected.CapabilityVersion != capability.Version || expected.InputDigest == "" {
		return nil, errors.New("v3: incomplete stream binding")
	}
	return &StreamValidator{
		capability: capability, expected: expected,
		nodes: make(map[string]struct{}), evidence: make(map[string]struct{}),
		seen: make(map[uint64]string), started: now,
	}, nil
}

// Receive returns true for an exact duplicate batch, which the caller should
// acknowledge without persisting twice. A sequence gap or changed duplicate
// is rejected. A final batch closes the stream.
func (v *StreamValidator) Receive(ctx context.Context, batch Batch, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if now.Before(v.started) || now.Sub(v.started) > time.Duration(v.capability.Limits.MaxDurationMS)*time.Millisecond {
		return false, errors.New("v3: stream duration limit exceeded")
	}
	env := batch.Envelope
	if env.ProtocolVersion != ProtocolVersion ||
		env.JobID != v.expected.JobID || env.OrganizationNonce != v.expected.OrganizationNonce ||
		env.PluginDigest != v.expected.PluginDigest ||
		env.CapabilityName != v.expected.CapabilityName ||
		env.CapabilityVersion != v.expected.CapabilityVersion ||
		env.InputDigest != v.expected.InputDigest ||
		env.ObservedAt.IsZero() || env.TraceID == "" {
		return false, errors.New("v3: batch binding mismatch")
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return false, err
	}
	if int64(len(raw)) > v.capability.Limits.MaxBatchBytes {
		return false, errors.New("v3: batch size limit exceeded")
	}
	hash := sha256.Sum256(raw)
	batchDigest := hex.EncodeToString(hash[:])
	if prior, ok := v.seen[env.Sequence]; ok {
		if prior == batchDigest {
			return true, nil
		}
		return false, errors.New("v3: duplicate sequence with changed payload")
	}
	if v.finished {
		return false, errors.New("v3: stream already finished")
	}
	if env.Sequence != v.next {
		return false, fmt.Errorf("v3: sequence gap at %d", env.Sequence)
	}
	if v.bytes+int64(len(raw)) > v.capability.Limits.MaxOutputBytes {
		return false, errors.New("v3: output size limit exceeded")
	}
	if v.resources+int64(len(batch.Resources)) > v.capability.Limits.MaxResources {
		return false, errors.New("v3: resource count limit exceeded")
	}
	if batch.Final {
		if batch.State != ResultComplete && batch.State != ResultPartial && batch.State != ResultFailed {
			return false, errors.New("v3: final batch requires result state")
		}
		if batch.State == ResultPartial && !v.capability.SupportsPartial {
			return false, errors.New("v3: undeclared partial result")
		}
	} else if batch.State != "" {
		return false, errors.New("v3: non-final batch declares result state")
	}
	newNodes := make(map[string]struct{}, len(batch.Resources))
	newEvidence := make(map[string]struct{}, len(batch.Evidence))
	for _, item := range batch.Evidence {
		if item.ID == "" || item.Source == "" ||
			len(item.Observation) > 0 && !json.Valid(item.Observation) {
			return false, errors.New("v3: invalid evidence")
		}
		if err := privacy.ValidateJSON(item.Observation); err != nil {
			return false, errors.New("v3: evidence contains non-public data")
		}
		if _, exists := v.evidence[item.ID]; exists {
			return false, errors.New("v3: duplicate evidence")
		}
		if _, exists := newEvidence[item.ID]; exists {
			return false, errors.New("v3: duplicate evidence in batch")
		}
		newEvidence[item.ID] = struct{}{}
	}
	newReferences := make([]string, 0)
	newSignals := make([]string, 0, len(batch.Signals))
	for _, node := range batch.Resources {
		if _, err := crn.Parse(node.CRN); err != nil {
			return false, fmt.Errorf("v3: invalid resource CRN: %w", err)
		}
		if _, exists := v.nodes[node.CRN]; exists {
			return false, errors.New("v3: duplicate resource")
		}
		if _, exists := newNodes[node.CRN]; exists {
			return false, errors.New("v3: duplicate resource in batch")
		}
		newNodes[node.CRN] = struct{}{}
		if !json.Valid(node.Properties) && len(node.Properties) > 0 {
			return false, errors.New("v3: invalid resource properties")
		}
		if err := privacy.ValidateJSON(node.Properties); err != nil {
			return false, errors.New("v3: resource contains non-public data")
		}
		newReferences = append(newReferences, node.EvidenceIDs...)
	}
	for _, edge := range batch.Relationships {
		if _, err := crn.Parse(edge.SourceCRN); err != nil {
			return false, fmt.Errorf("v3: invalid relationship source: %w", err)
		}
		if _, err := crn.Parse(edge.TargetCRN); err != nil {
			return false, fmt.Errorf("v3: invalid relationship target: %w", err)
		}
		if edge.Kind == "" {
			return false, errors.New("v3: relationship lacks kind")
		}
	}
	for _, signal := range batch.Signals {
		if _, err := crn.Parse(signal.CRN); err != nil {
			return false, fmt.Errorf("v3: invalid signal CRN: %w", err)
		}
		if signal.Kind == "" || !json.Valid(signal.Observation) {
			return false, errors.New("v3: invalid signal")
		}
		if err := privacy.ValidateJSON(signal.Observation); err != nil {
			return false, errors.New("v3: signal contains non-public data")
		}
		newReferences = append(newReferences, signal.EvidenceIDs...)
		newSignals = append(newSignals, signal.CRN)
	}
	for _, ref := range newReferences {
		if ref == "" {
			return false, errors.New("v3: empty evidence reference")
		}
	}
	for _, diagnostic := range batch.Diagnostics {
		if err := privacy.ValidateText(diagnostic); err != nil {
			return false, errors.New("v3: diagnostic contains non-public data")
		}
	}
	if batch.Final {
		for _, ref := range append(append([]string(nil), v.references...), newReferences...) {
			_, old := v.evidence[ref]
			_, current := newEvidence[ref]
			if !old && !current {
				return false, errors.New("v3: missing evidence reference")
			}
		}
		for _, edge := range append(append([]Relationship(nil), v.edges...), batch.Relationships...) {
			_, sourceOld := v.nodes[edge.SourceCRN]
			_, sourceNew := newNodes[edge.SourceCRN]
			_, targetOld := v.nodes[edge.TargetCRN]
			_, targetNew := newNodes[edge.TargetCRN]
			if !sourceOld && !sourceNew {
				return false, errors.New("v3: dangling relationship source")
			}
			if !targetOld && !targetNew {
				return false, errors.New("v3: dangling relationship target")
			}
		}
		for _, id := range append(append([]string(nil), v.signals...), newSignals...) {
			_, old := v.nodes[id]
			_, current := newNodes[id]
			if !old && !current {
				return false, errors.New("v3: signal references unknown resource")
			}
		}
	}
	// Mutate validator state only after every field in the batch passes.
	for _, node := range batch.Resources {
		v.nodes[node.CRN] = struct{}{}
	}
	for id := range newEvidence {
		v.evidence[id] = struct{}{}
	}
	v.references = append(v.references, newReferences...)
	v.edges = append(v.edges, batch.Relationships...)
	v.signals = append(v.signals, newSignals...)
	v.bytes += int64(len(raw))
	v.resources += int64(len(batch.Resources))
	v.seen[env.Sequence] = batchDigest
	v.next++
	if batch.Final {
		v.finished = true
	}
	return false, nil
}

func (v *StreamValidator) Finished() bool { return v.finished }
