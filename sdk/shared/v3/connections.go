package v3

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ConnectionField is one value a customer supplies for a connection method.
// Keep fields bounded and read-only; the plugin author decides the labels and
// help text, while the credential still determines what the plugin can read.
type ConnectionField struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Help      string `json:"help"`
	Required  bool   `json:"required"`
	MaxLength int    `json:"max_length"`
	MaxItems  int    `json:"max_items,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
}

// ConnectionMethod is the plugin-owned connection contract. It is data, never
// executable UI. Provider-specific setup belongs in the plugin's setup page or
// in the fields the plugin declares, not in CloudSlash core.
type ConnectionMethod struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Instructions string            `json:"instructions"`
	Permissions  []string          `json:"permissions"`
	Fields       []ConnectionField `json:"fields"`
	ReadOnly     bool              `json:"read_only"`
	// SetupURL is an optional HTTPS page that performs the provider setup.
	SetupURL string `json:"setup_url,omitempty"`
	// SetupMode is "return" when that page can return a finished connection to
	// Horizon, or "console" when it only opens a provider console. Empty is
	// treated as "console".
	SetupMode string `json:"setup_mode,omitempty"`
}

var connectionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// A connection method declares everything its provider can read. There is no
// count cap: a plugin owns its inventory surface and must be free to name every
// permission it needs, however many that is. Only each entry and the request
// body are bounded, because those are transport limits rather than statements
// about how much a provider may cover.
const permissionsBytes = 64 << 10

// Validate applies the same data contract the hosted server enforces.
func (m ConnectionMethod) Validate() error {
	if m.ID == "" || len(m.ID) > 100 || m.Title == "" || len(m.Title) > 100 ||
		m.Instructions == "" || len(m.Instructions) > 4000 ||
		len(m.Permissions) == 0 ||
		len(m.Fields) == 0 || len(m.Fields) > 16 || !m.ReadOnly {
		return errors.New("v3: invalid connection method")
	}
	declared := 0
	for _, permission := range m.Permissions {
		if strings.TrimSpace(permission) == "" || len(permission) > 200 {
			return errors.New("v3: invalid connection permission")
		}
		declared += len(permission)
	}
	if declared > permissionsBytes {
		return errors.New("v3: connection permissions exceed the size bound")
	}
	seen := map[string]bool{}
	for _, field := range m.Fields {
		if !connectionKeyPattern.MatchString(field.Key) || seen[field.Key] ||
			field.Label == "" || len(field.Label) > 100 || len(field.Help) > 1000 ||
			field.MaxLength < 1 || field.MaxLength > 4096 || len(field.Pattern) > 256 {
			return errors.New("v3: invalid connection field")
		}
		seen[field.Key] = true
		switch field.Type {
		case "text", "secret", "string_list":
		default:
			return errors.New("v3: unsupported connection field type")
		}
		if field.Type == "string_list" {
			if field.MaxItems < 1 || field.MaxItems > 20 {
				return errors.New("v3: invalid connection field list bound")
			}
		} else if field.MaxItems != 0 {
			return errors.New("v3: max_items is only valid for string_list")
		}
		if field.Pattern != "" {
			if _, err := regexp.Compile(field.Pattern); err != nil {
				return errors.New("v3: invalid connection field pattern")
			}
		}
	}
	if m.SetupURL != "" {
		u, err := url.Parse(m.SetupURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(m.SetupURL) > 2048 {
			return errors.New("v3: setup_url must be an HTTPS URL without credentials")
		}
	}
	if m.SetupMode != "" && m.SetupMode != "return" && m.SetupMode != "console" {
		return errors.New(`v3: setup_mode must be "return" or "console"`)
	}
	if m.SetupMode == "return" && m.SetupURL == "" {
		return errors.New(`v3: setup_mode "return" requires setup_url`)
	}
	return nil
}

// ConnectionMethodsDigest binds consent text, fields and permissions to a
// release. It matches the hosted server's digest exactly.
func ConnectionMethodsDigest(methods []ConnectionMethod) (string, error) {
	if len(methods) == 0 || len(methods) > 8 {
		return "", errors.New("v3: one to eight connection methods are required")
	}
	seen := map[string]bool{}
	for _, method := range methods {
		if method.Validate() != nil || seen[method.ID] {
			return "", errors.New("v3: invalid or duplicate connection method")
		}
		seen[method.ID] = true
	}
	raw, err := json.Marshal(methods)
	if err != nil {
		return "", errors.New("v3: could not encode connection methods")
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
