package v3

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/crn"
)

func sourceCapability() Capability {
	return Capability{
		Name: "noncloud.inventory", Version: "1.0.0", Role: Source, Effect: Read,
		Environments: []Environment{Local, Hosted, CustomerRunner},
		InputSchema:  "scan.request/v1", OutputSchema: "scan.batch/v1",
		Limits:               Limits{MaxBatchBytes: 4096, MaxOutputBytes: 8192, MaxResources: 2, MaxDurationMS: 10000, MaxConcurrency: 1},
		SupportsCancellation: true, SupportsPartial: true,
	}
}

func TestCapabilityFailClosed(t *testing.T) {
	c := sourceCapability()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.AvailableIn(Hosted) {
		t.Fatal("declared hosted capability unavailable")
	}
	c.Effect = Effect("mutate")
	if c.AvailableIn(Hosted) {
		t.Fatal("mutation effect accepted")
	}
	c = sourceCapability()
	c.OutputSchema = "scan.batch/v99"
	if c.AvailableIn(Hosted) {
		t.Fatal("unknown schema accepted")
	}
	c = sourceCapability()
	c.Name = "third-party-unseen"
	if err := c.Validate(); err != nil {
		t.Fatalf("unknown capability name rejected: %v", err)
	}
}

func TestStreamReplayAndBoundaries(t *testing.T) {
	c := sourceCapability()
	now := time.Now().UTC()
	expected := Envelope{
		ProtocolVersion: ProtocolVersion, JobID: "job-1", OrganizationNonce: "nonce",
		PluginDigest: "sha256:manifest", CapabilityName: c.Name, CapabilityVersion: c.Version,
		InputDigest: "sha256:input",
	}
	v, err := NewStreamValidator(c, expected, now)
	if err != nil {
		t.Fatal(err)
	}
	a := crn.New("third-party", "", "svc", "kind", "", "a:1").String()
	b := crn.New("third-party", "", "svc", "kind", "", "b").String()
	first := Batch{
		Envelope: expected, Resources: []Resource{{CRN: a, Properties: json.RawMessage(`{"active":true}`)}},
		Relationships: []Relationship{{SourceCRN: a, TargetCRN: b, Kind: "uses"}},
	}
	first.Envelope.ObservedAt = now
	first.Envelope.TraceID = "trace"
	if duplicate, err := v.Receive(context.Background(), first, now); err != nil || duplicate {
		t.Fatalf("first: %v, duplicate=%v", err, duplicate)
	}
	if duplicate, err := v.Receive(context.Background(), first, now); err != nil || !duplicate {
		t.Fatalf("replay: %v, duplicate=%v", err, duplicate)
	}
	tampered := first
	tampered.Resources = []Resource{{CRN: "crn:devi:x::s:t::z"}}
	if _, err := v.Receive(context.Background(), tampered, now); err == nil {
		t.Fatal("changed duplicate accepted")
	}
	final := Batch{Envelope: expected, Resources: []Resource{{CRN: b}}, Final: true, State: ResultPartial}
	final.Envelope.Sequence = 1
	final.Envelope.ObservedAt = now
	final.Envelope.TraceID = "trace"
	if _, err := v.Receive(context.Background(), final, now); err != nil {
		t.Fatal(err)
	}
	if !v.Finished() {
		t.Fatal("final batch did not finish")
	}
	if duplicate, err := v.Receive(context.Background(), final, now); err != nil || !duplicate {
		t.Fatalf("final replay: %v, duplicate=%v", err, duplicate)
	}
}

func TestStreamRejectsGapsOversizeAndDanglingEdges(t *testing.T) {
	c := sourceCapability()
	now := time.Now().UTC()
	expected := Envelope{ProtocolVersion: ProtocolVersion, JobID: "j", OrganizationNonce: "n", PluginDigest: "d", CapabilityName: c.Name, CapabilityVersion: c.Version, InputDigest: "i"}
	newValidator := func() *StreamValidator {
		v, err := NewStreamValidator(c, expected, now)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	batch := Batch{Envelope: expected, Final: true, State: ResultComplete}
	batch.Envelope.ObservedAt = now
	batch.Envelope.TraceID = "t"
	batch.Envelope.Sequence = 1
	if _, err := newValidator().Receive(context.Background(), batch, now); err == nil {
		t.Fatal("sequence gap accepted")
	}
	batch.Envelope.Sequence = 0
	batch.Relationships = []Relationship{{SourceCRN: "crn:devi:x::s:t::a", TargetCRN: "crn:devi:x::s:t::b", Kind: "uses"}}
	v := newValidator()
	if _, err := v.Receive(context.Background(), batch, now); err == nil || v.Finished() {
		t.Fatal("dangling edge accepted or state mutated")
	}
	batch.Relationships = nil
	batch.Signals = []Signal{{CRN: "crn:devi:x::s:t::missing", Kind: "observed", Observation: json.RawMessage(`{"value":1}`)}}
	if _, err := newValidator().Receive(context.Background(), batch, now); err == nil {
		t.Fatal("unbound signal accepted")
	}
	batch.Signals = nil
	batch.Diagnostics = []string{strings.Repeat("x", 4096)}
	if _, err := newValidator().Receive(context.Background(), batch, now); err == nil {
		t.Fatal("oversized batch accepted")
	}
}

func TestCapabilityRejectsDurationOverflow(t *testing.T) {
	capability := sourceCapability()
	capability.Limits.MaxDurationMS = 9223372036854775807
	if err := capability.Validate(); err == nil {
		t.Fatal("accepted overflowing timer duration")
	}
}
