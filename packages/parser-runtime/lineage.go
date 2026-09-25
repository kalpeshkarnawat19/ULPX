package parser_runtime

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	normalizedPathRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$`)
	validLocatorTypes   = map[string]bool{"key": true, "json_pointer": true, "offset": true, "regex_group": true}
	validExtractors     = map[string]bool{
		"key_value":     true,
		"json_pointer":  true,
		"regex_capture": true,
		"cef_parse":     true,
		"leef_parse":    true,
		"syslog_parse":  true,
		"kv":            true,
		"csv_parse":     true,
		"csv":           true,
	}
	validTransformations = map[string]bool{
		"trim":        true,
		"lowercase":   true,
		"uppercase":   true,
		"integer":     true,
		"float":       true,
		"boolean":     true,
		"ip":          true,
		"timestamp":   true,
		"enum_map":    true,
		"split":       true,
		"join":        true,
		"substring":   true,
	}
	validEvidence = map[string]bool{
		"alias_match":                    true,
		"type_match":                     true,
		"event_family_context":           true,
		"schema_description_similarity": true,
		"value_profile":                  true,
	}
	validReviewStatuses = map[string]bool{
		"AUTO_ACCEPTED":  true,
		"HUMAN_APPROVED": true,
		"ABSTAINED":      true,
		"REJECTED":       true,
	}
)

// RawLocator points to the raw evidence for an extracted field.
type RawLocator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// FieldLineage models forensic provenance conforming to packages/contracts/field_lineage.schema.json.
type FieldLineage struct {
	NormalizedPath  string     `json:"normalized_path"`
	RawLocator      RawLocator `json:"raw_locator"`
	Extractor       string     `json:"extractor"`
	Transformations []string   `json:"transformations"`
	MappingScore    float64    `json:"mapping_score"`
	MappingEvidence []string   `json:"mapping_evidence"`
	ReviewStatus    string     `json:"review_status"`
}

// Validate checks that FieldLineage satisfies field_lineage.schema.json.
func (fl *FieldLineage) Validate() error {
	if fl == nil {
		return fmt.Errorf("field lineage is nil")
	}

	if !normalizedPathRegex.MatchString(fl.NormalizedPath) {
		return fmt.Errorf("invalid normalized_path %q: must match dotted identifier pattern", fl.NormalizedPath)
	}

	if !validLocatorTypes[fl.RawLocator.Type] {
		return fmt.Errorf("invalid raw_locator.type %q: must be one of key, json_pointer, offset, regex_group", fl.RawLocator.Type)
	}
	if len(strings.TrimSpace(fl.RawLocator.Value)) == 0 {
		return fmt.Errorf("raw_locator.value cannot be empty")
	}

	if !validExtractors[fl.Extractor] {
		return fmt.Errorf("invalid extractor %q: must be one of key_value, json_pointer, regex_capture, cef_parse, leef_parse, syslog_parse, kv, csv_parse, csv", fl.Extractor)
	}

	for _, t := range fl.Transformations {
		if !validTransformations[t] {
			return fmt.Errorf("invalid transformation %q", t)
		}
	}

	if fl.MappingScore < 0.0 || fl.MappingScore > 1.0 {
		return fmt.Errorf("mapping_score %.2f must be between 0.0 and 1.0", fl.MappingScore)
	}

	if len(fl.MappingEvidence) == 0 {
		return fmt.Errorf("mapping_evidence must contain at least 1 item")
	}
	for _, e := range fl.MappingEvidence {
		if !validEvidence[e] {
			return fmt.Errorf("invalid mapping_evidence item %q", e)
		}
	}

	if !validReviewStatuses[fl.ReviewStatus] {
		return fmt.Errorf("invalid review_status %q: must be AUTO_ACCEPTED, HUMAN_APPROVED, ABSTAINED, or REJECTED", fl.ReviewStatus)
	}

	return nil
}

// ToJSON serializes FieldLineage to JSON bytes.
func (fl *FieldLineage) ToJSON() ([]byte, error) {
	return json.Marshal(fl)
}

// FindRawByteOffset searches raw bytes for exact token boundaries to establish byte span evidence.
// Scope guard: returns -1, -1, false if token cannot be established with certainty (zero fabrication).
func FindRawByteOffset(raw []byte, token string) (int, int, bool) {
	if len(raw) == 0 || len(token) == 0 {
		return -1, -1, false
	}
	rawStr := string(raw)
	idx := strings.Index(rawStr, token)
	if idx < 0 {
		return -1, -1, false
	}
	return idx, idx + len(token), true
}

// NormalizeExtractor maps body parser format to schema-approved extractor enum.
func NormalizeExtractor(bodyParserType string) string {
	switch bodyParserType {
	case "key_value", "kv":
		return "kv"
	case "syslog":
		return "syslog_parse"
	case "cef":
		return "cef_parse"
	case "leef":
		return "leef_parse"
	case "json":
		return "json_pointer"
	case "csv":
		return "csv_parse"
	default:
		return "key_value"
	}
}

// BuildFieldLineage constructs and validates a FieldLineage instance.
func BuildFieldLineage(
	normalizedPath string,
	sourceField string,
	bodyParserType string,
	transformations []string,
	rawText string,
	val interface{},
) (*FieldLineage, error) {
	// 1. Determine extractor name matching schema enum
	extractor := NormalizeExtractor(bodyParserType)

	// 2. Determine raw locator
	var locatorType string
	var locatorValue string

	switch extractor {
	case "json_pointer":
		locatorType = "json_pointer"
		locatorValue = "/" + strings.ReplaceAll(sourceField, ".", "/")
	case "csv_parse", "csv":
		locatorType = "key"
		locatorValue = sourceField
	default:
		lowerRaw := strings.ToLower(rawText)
		lowerField := strings.ToLower(sourceField)
		if strings.Contains(lowerRaw, lowerField) {
			locatorType = "key"
			locatorValue = sourceField
		} else {
			// For positional header fields in Syslog, CEF, or LEEF, verify that the extracted
			// value actually exists in the raw text evidence.
			valStr := fmt.Sprintf("%v", val)
			if len(valStr) > 0 && strings.Contains(lowerRaw, strings.ToLower(valStr)) {
				locatorType = "key"
				locatorValue = sourceField
			} else {
				// Scope guard: do not fabricate locator
				return nil, fmt.Errorf("source field %q and value %q not found in raw payload: cannot establish evidence without fabrication", sourceField, valStr)
			}
		}
	}

	// 3. Filter transformations to schema-approved subset
	var cleanTransforms []string
	for _, t := range transformations {
		if validTransformations[t] {
			cleanTransforms = append(cleanTransforms, t)
		}
	}

	lineage := &FieldLineage{
		NormalizedPath: normalizedPath,
		RawLocator: RawLocator{
			Type:  locatorType,
			Value: locatorValue,
		},
		Extractor:       extractor,
		Transformations: cleanTransforms,
		MappingScore:    1.0,
		MappingEvidence: []string{"alias_match", "type_match", "event_family_context"},
		ReviewStatus:    "AUTO_ACCEPTED",
	}

	if err := lineage.Validate(); err != nil {
		return nil, fmt.Errorf("validating constructed lineage: %w", err)
	}

	return lineage, nil
}
