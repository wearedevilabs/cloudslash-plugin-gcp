// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package crn

// InvalidStoredName is a report row for an existing identifier that cannot
// enter the v2 graph. It intentionally carries no suggested replacement.
type InvalidStoredName struct {
	Raw   string `json:"raw"`
	Error string `json:"error"`
}

// AuditStoredNames reports malformed stored names without rewriting them.
// Callers can serialize the rows as a migration report and supply an explicit
// operator-approved mapping before changing resource identity.
func AuditStoredNames(raw []string) []InvalidStoredName {
	var invalid []InvalidStoredName
	for _, name := range raw {
		if _, err := Parse(name); err != nil {
			invalid = append(invalid, InvalidStoredName{Raw: name, Error: err.Error()})
		}
	}
	return invalid
}
