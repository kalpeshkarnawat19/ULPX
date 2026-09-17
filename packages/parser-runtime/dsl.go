// Package parser_runtime provides deterministic Parser DSL execution in Go
// conforming to ULPF-X Build Guide Stage 3 and PRD Section 5.
//
// Strictly zero eval, exec, shell, or dynamic code generation.
package parser_runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

var (
	parserIDRegex  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	semverRegex    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	mapToRegex     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$`)
	validFormats   = map[string]bool{"syslog": true, "json": true, "cef": true, "leef": true, "key_value": true, "csv": true}
	validBodyTypes = map[string]bool{"syslog": true, "json": true, "cef": true, "leef": true, "key_value": true, "csv": true}
	validFieldTypes = map[string]bool{
		"string":    true,
		"integer":   true,
		"float":     true,
		"boolean":   true,
		"ip":        true,
		"timestamp": true,
	}
)

// ParserInfo contains parser metadata.
type ParserInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// MatchConfig specifies matching criteria for assigning this parser to raw events.
type MatchConfig struct {
	Format       string   `json:"format"`
	BodyContains []string `json:"body_contains,omitempty"`
}

// BodyParserConfig defines intermediate structural extraction rules.
type BodyParserConfig struct {
	Type              string   `json:"type"`
	PairSeparator     string   `json:"pair_separator,omitempty"`
	KeyValueSeparator string   `json:"key_value_separator,omitempty"`
	Delimiter         string   `json:"delimiter,omitempty"`
	Headers           []string `json:"headers,omitempty"`
}

// FieldSpec defines normalization and transformation for a single extracted field.
type FieldSpec struct {
	Type            string            `json:"type"`
	MapTo           string            `json:"map_to"`
	Enum            map[string]string `json:"enum,omitempty"`
	Transformations []string          `json:"transformations,omitempty"`
}

// UnknownFieldsConfig specifies how to treat unmapped fields.
type UnknownFieldsConfig struct {
	Policy string `json:"policy"`
}

// RawConfig specifies whether to preserve raw event bytes.
type RawConfig struct {
	Preserve bool `json:"preserve"`
}

// ParserSpec represents declarative parser data conforming to parser_spec.schema.json.
type ParserSpec struct {
	Schema        string               `json:"$schema,omitempty"`
	DSLVersion    string               `json:"dsl_version"`
	Parser        ParserInfo           `json:"parser"`
	Match         MatchConfig          `json:"match"`
	BodyParser    BodyParserConfig     `json:"body_parser"`
	Fields        map[string]FieldSpec `json:"fields"`
	UnknownFields UnknownFieldsConfig  `json:"unknown_fields"`
	Raw           RawConfig            `json:"raw"`
}

// LoadParserSpecJSON parses and strictly validates a ParserSpec JSON payload.
func LoadParserSpecJSON(data []byte) (*ParserSpec, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var spec ParserSpec
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decoding parser spec: %w", err)
	}

	if err := ValidateParserSpec(&spec); err != nil {
		return nil, fmt.Errorf("validating parser spec: %w", err)
	}

	return &spec, nil
}

// ValidateParserSpec strictly validates spec against parser_spec.schema.json constraints.
func ValidateParserSpec(spec *ParserSpec) error {
	if spec == nil {
		return fmt.Errorf("parser spec is nil")
	}

	if spec.DSLVersion != "1.0" {
		return fmt.Errorf("invalid dsl_version %q: must be '1.0'", spec.DSLVersion)
	}

	if !parserIDRegex.MatchString(spec.Parser.ID) {
		return fmt.Errorf("invalid parser.id %q: must match ^[a-z0-9][a-z0-9._-]*$", spec.Parser.ID)
	}

	if !semverRegex.MatchString(spec.Parser.Version) {
		return fmt.Errorf("invalid parser.version %q: must match semver ^[0-9]+\\.[0-9]+\\.[0-9]+$", spec.Parser.Version)
	}

	if !validFormats[spec.Match.Format] {
		return fmt.Errorf("invalid match.format %q: must be one of syslog, json, cef, leef, key_value, csv", spec.Match.Format)
	}

	if !validBodyTypes[spec.BodyParser.Type] {
		return fmt.Errorf("invalid body_parser.type %q: must be one of syslog, json, cef, leef, key_value, csv", spec.BodyParser.Type)
	}

	if len(spec.Fields) == 0 {
		return fmt.Errorf("fields must contain at least 1 property")
	}

	for fieldName, fieldSpec := range spec.Fields {
		if fieldName == "" {
			return fmt.Errorf("field name cannot be empty")
		}

		if !validFieldTypes[fieldSpec.Type] {
			return fmt.Errorf("field %q has invalid type %q: must be string, integer, float, boolean, ip, or timestamp", fieldName, fieldSpec.Type)
		}

		if !mapToRegex.MatchString(fieldSpec.MapTo) {
			return fmt.Errorf("field %q has invalid map_to %q: must match dotted identifier pattern", fieldName, fieldSpec.MapTo)
		}

		for _, op := range fieldSpec.Transformations {
			if !IsWhitelistedOperation(op) {
				return fmt.Errorf("field %q uses unwhitelisted operation %q", fieldName, op)
			}
		}
	}

	if spec.UnknownFields.Policy != "preserve" {
		return fmt.Errorf("invalid unknown_fields.policy %q: must be 'preserve'", spec.UnknownFields.Policy)
	}

	if !spec.Raw.Preserve {
		return fmt.Errorf("raw.preserve must be true (raw bytes retention is non-negotiable)")
	}

	return nil
}
