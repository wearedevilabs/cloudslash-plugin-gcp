// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package manifest

import (
	"encoding/json"
)

func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
