// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

const validProvider = `{
  "schema_version": 2,
  "name": "aws",
  "version": "2.1.0",
  "type": "provider",
  "description": "AWS provider plugin",
  "author": { "name": "DrSkyle", "url": "https://github.com/DrSkyle" },
  "tags": ["aws", "cloud"],
  "cloudslash_min_version": "2.0.0",
  "entrypoints": { "binary": { "command": "cloudslash-plugin-aws", "protocol": "grpc+goplugin" } },
  "assets": [
    { "platform": "darwin/arm64", "url": "https://example.com/a.tar.gz", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { "platform": "linux/amd64", "url": "https://example.com/b.tar.gz", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
  ]
}`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validProvider))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Name != "aws" || m.Type != "provider" || m.Version != "2.1.0" {
		t.Fatalf("unexpected fields: %+v", m)
	}
	if !m.IsBinaryType() {
		t.Fatal("provider must be a binary type")
	}
	a, err := m.AssetFor("darwin/arm64")
	if err != nil || a.URL != "https://example.com/a.tar.gz" {
		t.Fatalf("AssetFor: %v %+v", err, a)
	}
	if _, err := m.AssetFor("windows/386"); err == nil {
		t.Fatal("expected error for missing platform")
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"wrong schema", `{"schema_version":1,"name":"x","version":"1.0.0","type":"provider","description":"d"}`, "schema_version"},
		{"bad name", `{"schema_version":2,"name":"Bad_Name!","version":"1.0.0","type":"provider","description":"d"}`, "invalid name"},
		{"no version", `{"schema_version":2,"name":"x","type":"provider","description":"d"}`, "version is required"},
		{"bad semver", `{"schema_version":2,"name":"x","version":"latest","type":"provider","description":"d"}`, "semver"},
		{"no type", `{"schema_version":2,"name":"x","version":"1.0.0","description":"d"}`, "type is required"},
		{"provider no binary", `{"schema_version":2,"name":"x","version":"1.0.0","type":"provider","description":"d"}`, "entrypoints.binary"},
		{"asset no sha", `{"schema_version":2,"name":"x","version":"1.0.0","type":"provider","description":"d","entrypoints":{"binary":{"command":"x"}},"assets":[{"platform":"linux/amd64","url":"https://e.com/x"}]}`, "sha256"},
		{"policy no glob", `{"schema_version":2,"name":"x","version":"1.0.0","type":"policy-pack","description":"d"}`, "entrypoints.policies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParseUnknownTypeAllowed(t *testing.T) {
	// Open-ended types install as data-only plugins; validation must not
	// reject types the core does not know about.
	doc := `{"schema_version":2,"name":"my-thing","version":"0.1.0","type":"custom-widget","description":"anything"}`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatalf("open-ended type rejected: %v", err)
	}
}

func TestHostedProviderNeedsNoLocalBinary(t *testing.T) {
	doc := `{"schema_version":2,"name":"hosted-aws","version":"1.0.0","type":"provider","description":"Hosted scan","capabilities":{"scan":true},"entrypoints":{"hosted":{"endpoint":"grpcs://plugins.example.com","protocol":"grpcs+cloudslash"}}}`
	m, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("hosted plugin rejected: %v", err)
	}
	if m.IsBinaryType() {
		t.Fatal("hosted-only plugin treated as a local binary")
	}
	bad := strings.Replace(doc, "grpcs://plugins.example.com", "grpcs://127.0.0.1:8080", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("accepted unsafe hosted port")
	}
}

func TestConnectionAndCapabilityContracts(t *testing.T) {
	doc := `{
  "schema_version": 2,
  "name": "example-source",
  "version": "1.0.0",
  "type": "provider",
  "description": "Example hosted source",
  "capabilities": {"discovery": true, "analyze": true},
  "capability_contracts": {
    "discovery": {"version":"1.0.0", "effect":"read", "environments":["local","hosted"]},
    "analyze": {"version":"1.0.0", "effect":"compute", "environments":["local","hosted"]}
  },
  "connections": [{
    "id":"delegated_access",
    "label":"Delegated access",
    "flow":"form",
    "environments":["hosted"],
    "fields":[
      {"key":"identity", "label":"Identity", "type":"text", "required":true},
      {"key":"nonce", "label":"Verification value", "type":"secret", "secret":true, "generated":true}
    ]
  }],
  "entrypoints":{"hosted":{"endpoint":"grpcs://plugins.example.com","protocol":"grpcs+cloudslash"}}
}`
	m, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse connection contract: %v", err)
	}
	if got := m.CapabilityContracts["analyze"].Environments; len(got) != 2 {
		t.Fatalf("unexpected analyze environments: %v", got)
	}
	if len(m.Connections) != 1 || !m.Connections[0].Fields[1].Secret {
		t.Fatalf("connection contract lost: %+v", m.Connections)
	}
}

func TestConnectionContractsRejectUnsafeOrMalformedDefinitions(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"contract without capability", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","capability_contracts":{"scan":{"version":"1.0.0","effect":"read","environments":["hosted"]}}}`, "requires an enabled capability"},
		{"mutating effect", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","capabilities":{"run":true},"capability_contracts":{"run":{"version":"1.0.0","effect":"mutate","environments":["local"]}}}`, "invalid effect"},
		{"mutation permission", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","permissions":{"example":{"mutate":["resource.delete"]}}}`, "cannot declare mutation access"},
		{"unknown environment", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","connections":[{"id":"login","label":"Login","flow":"oauth2","environments":["browser"]}]}`, "invalid environment"},
		{"empty form", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","connections":[{"id":"login","label":"Login","flow":"form","environments":["hosted"]}]}`, "requires fields"},
		{"secret text", `{"schema_version":2,"name":"x","version":"1.0.0","type":"custom","description":"d","connections":[{"id":"login","label":"Login","flow":"form","environments":["hosted"],"fields":[{"key":"token","label":"Token","type":"text","secret":true}]}]}`, "non-secret-capable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestConvertV1(t *testing.T) {
	v1yaml := `
name: aws
version: 2.0.0
type: plugin
author: DrSkyle
description: AWS provider plugin
tags: [aws, cloud]
cloudslash_min_version: 2.0.0
binaries:
  darwin/arm64: https://example.com/a.tar.gz
  linux/amd64: https://example.com/b.tar.gz
checksums:
  darwin/arm64: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
capabilities:
  discovery: true
  pricing: false
`
	v1, err := ParseV1YAML([]byte(v1yaml))
	if err != nil {
		t.Fatalf("parse v1: %v", err)
	}
	m, err := ConvertV1(v1)
	// linux/amd64 has no checksum -> dropped, reported as a partial-conversion note
	if err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("expected dropped-asset note, got %v", err)
	}
	if m.SchemaVersion != 2 || m.Name != "aws" || len(m.Assets) != 1 {
		t.Fatalf("unexpected conversion: %+v", m)
	}
	// linux/amd64 had no checksum -> dropped, reported via error
	if m.Assets[0].Platform != "darwin/arm64" {
		t.Fatalf("wrong asset kept: %+v", m.Assets)
	}
	if m.Type != "plugin" {
		t.Fatalf("type should pass through: %q", m.Type)
	}
	if !m.Capabilities["discovery"] || m.Capabilities["pricing"] {
		t.Fatalf("capabilities lost: %+v", m.Capabilities)
	}
	if m.Entrypoints == nil || m.Entrypoints.Binary.Command != "cloudslash-plugin-aws" {
		t.Fatalf("entrypoint not inferred: %+v", m.Entrypoints)
	}
}

func TestCanonicalJSONStable(t *testing.T) {
	m1, _ := Parse([]byte(validProvider))
	// reformat input (whitespace variance) and reparse
	var pretty map[string]interface{}
	json.Unmarshal([]byte(validProvider), &pretty)
	reformatted, _ := json.MarshalIndent(pretty, "", "  ")
	m2, err := Parse(reformatted)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	c1, _ := m1.CanonicalJSON()
	c2, _ := m2.CanonicalJSON()
	if string(c1) != string(c2) {
		t.Fatalf("canonical JSON not stable:\n%s\n%s", c1, c2)
	}
}
