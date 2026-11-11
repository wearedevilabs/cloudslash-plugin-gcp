// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package crn implements the version 2 CloudSlash Resource Name contract.
// See docs/architecture/crn-v2.md in the core repository.
package crn

import (
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"
)

const Prefix = "crn:devi:"
const MaxLength = 2048

// CRN uniquely identifies a resource. SourceName is the public accessor.
// Provider remains the stored field for source compatibility and stable
// equality with existing Go map keys.
type CRN struct {
	Provider string // Deprecated: use SourceName to read the source.
	Region   string // Scope in the wire format; may be empty.
	Service  string
	Type     string
	Account  string // May be empty.
	ID       string
}

var (
	ErrInvalidFormat = errors.New("crn: invalid format or prefix")
	ErrEmptyFields   = errors.New("crn: essential fields cannot be empty")
	ErrTooLong       = errors.New("crn: exceeds maximum length")
	ErrNonCanonical  = errors.New("crn: non-canonical encoding")
)

// New constructs a CRN. For untrusted inputs, call Validate or NewChecked.
func New(source, scope, service, typ, account, id string) CRN {
	return CRN{Provider: source, Region: scope, Service: service, Type: typ, Account: account, ID: id}
}

// NewChecked constructs and validates a CRN before it is persisted.
func NewChecked(source, scope, service, typ, account, id string) (CRN, error) {
	c := New(source, scope, service, typ, account, id)
	return c, c.Validate()
}

// SourceName reads the public source field, including legacy Provider literals.
func (c CRN) SourceName() string {
	return c.Provider
}

// Scope reads the wire-format scope, historically called Region.
func (c CRN) Scope() string { return c.Region }

// Validate rejects empty required fields, invalid UTF-8, and oversized CRNs.
func (c CRN) Validate() error {
	fields := []string{c.SourceName(), c.Region, c.Service, c.Type, c.Account, c.ID}
	if fields[0] == "" || fields[2] == "" || fields[3] == "" || fields[5] == "" {
		return ErrEmptyFields
	}
	for _, field := range fields {
		if !utf8.ValidString(field) {
			return ErrInvalidFormat
		}
	}
	if len(c.String()) > MaxLength {
		return ErrTooLong
	}
	return nil
}

// Parse accepts only the canonical eight-segment serialization. Malformed
// stored identifiers must be reported and migrated explicitly by callers.
func Parse(raw string) (CRN, error) {
	if len(raw) > MaxLength {
		return CRN{}, ErrTooLong
	}
	if !strings.HasPrefix(raw, Prefix) {
		return CRN{}, ErrInvalidFormat
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 8 {
		return CRN{}, ErrInvalidFormat
	}
	var decoded [6]string
	for i := range decoded {
		value, err := url.PathUnescape(parts[i+2])
		if err != nil || !utf8.ValidString(value) {
			return CRN{}, ErrInvalidFormat
		}
		decoded[i] = value
	}
	c := New(decoded[0], decoded[1], decoded[2], decoded[3], decoded[4], decoded[5])
	if err := c.Validate(); err != nil {
		return CRN{}, err
	}
	if c.String() != raw {
		return CRN{}, ErrNonCanonical
	}
	return c, nil
}

// String serializes the six data segments. The colon delimiter is always
// escaped within a segment, including IDs containing provider-native names.
func (c CRN) String() string {
	fields := [...]string{c.SourceName(), c.Region, c.Service, c.Type, c.Account, c.ID}
	var sb strings.Builder
	sb.Grow(64)
	sb.WriteString(Prefix)
	for i, field := range fields {
		if i != 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(strings.ReplaceAll(url.PathEscape(field), ":", "%3A"))
	}
	return sb.String()
}
