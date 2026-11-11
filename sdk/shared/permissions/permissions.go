// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package permissions holds the plugin-declared permission catalogs. Plugins
// contribute their required IAM actions via RegisterCatalog so the core never
// hardcodes provider-specific policy vocabulary.
package permissions

// PermissionSet groups the actions a scanner needs for a resource family.
// The Action strings are opaque to the core; the AWS plugin populates them with
// IAM actions, while other providers populate their own policy vocabularies.
type PermissionSet struct {
	ResourceFamily string   // canonical family, e.g. "compute", "object-storage"
	ReadActions    []string // e.g. "ec2:DescribeInstances"
	MutateActions  []string // e.g. "ec2:StopInstances"
}

// Catalog maps a scanner name to the permission sets it requires.
// Plugins contribute entries via RegisterCatalog so the core never hardcodes
// provider actions.
type Catalog struct {
	Sets []PermissionSet
}

var globalCatalog = map[string]*Catalog{}

// RegisterCatalog registers or replaces a scanner's permission catalog.
func RegisterCatalog(scanner string, c *Catalog) {
	globalCatalog[scanner] = c
}

// GetCatalog returns the registered catalog for a scanner, or nil.
func GetCatalog(scanner string) *Catalog {
	return globalCatalog[scanner]
}

// AllReadActions returns every read action across every registered catalog.
func AllReadActions() []string {
	var out []string
	for _, c := range globalCatalog {
		for _, s := range c.Sets {
			out = append(out, s.ReadActions...)
		}
	}
	return out
}

// AllMutateActions returns every mutate action across every registered catalog.
func AllMutateActions() []string {
	var out []string
	for _, c := range globalCatalog {
		for _, s := range c.Sets {
			out = append(out, s.MutateActions...)
		}
	}
	return out
}
