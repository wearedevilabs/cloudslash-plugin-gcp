// SPDX-License-Identifier: Apache-2.0
package v3

import (
	"errors"
	"regexp"
	"unicode"
)

// Presentation contains data-only view hints over resource properties. It
// grants no query, script, HTML, network, or execution authority.
type Presentation struct {
	SchemaVersion string       `json:"schema_version"`
	LabelFields   []string     `json:"label_fields,omitempty"`
	Metrics       []MetricView `json:"metrics,omitempty"`
	Series        []SeriesView `json:"series,omitempty"`
}
type MetricView struct {
	Field  string `json:"field"`
	Label  string `json:"label"`
	Format string `json:"format"`
}
type SeriesView struct {
	Field  string `json:"field"`
	Label  string `json:"label"`
	XField string `json:"x_field"`
	YField string `json:"y_field"`
}

var viewField = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`)

func (p Presentation) Validate() error {
	invalid := errors.New("v3: invalid declarative presentation")
	if p.SchemaVersion != "1" || len(p.LabelFields) > 3 || len(p.Metrics) > 8 || len(p.Series) > 4 {
		return invalid
	}
	for _, field := range p.LabelFields {
		if !viewField.MatchString(field) {
			return invalid
		}
	}
	labelOK := func(label string) bool {
		if len(label) == 0 || len(label) > 80 {
			return false
		}
		for _, r := range label {
			if unicode.IsControl(r) {
				return false
			}
		}
		return true
	}
	for _, metric := range p.Metrics {
		if !viewField.MatchString(metric.Field) || !labelOK(metric.Label) {
			return invalid
		}
		switch metric.Format {
		case "number", "percent", "seconds":
		default:
			return invalid
		}
	}
	for _, series := range p.Series {
		if !viewField.MatchString(series.Field) || !viewField.MatchString(series.XField) || !viewField.MatchString(series.YField) || !labelOK(series.Label) {
			return invalid
		}
	}
	return nil
}
