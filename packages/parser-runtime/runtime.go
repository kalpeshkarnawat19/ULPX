package parser_runtime

import (
	"fmt"
	"strings"
	"time"
)

// FieldLineage tracks how a canonical field was derived from raw telemetry.
type FieldLineage struct {
	SourceField string  `json:"source_field"`
	Rule        string  `json:"rule"`
	Confidence  float64 `json:"confidence"`
}

// ParseResult encapsulates the output of executing a ParserSpec against raw telemetry.
type ParseResult struct {
	Extracted     map[string]interface{}  `json:"extracted"`
	UnknownFields map[string]interface{}  `json:"unknown_fields,omitempty"`
	Raw           string                  `json:"raw"`
	Duration      time.Duration           `json:"duration"`
	Lineage       map[string]FieldLineage `json:"lineage,omitempty"`
	Errors        []string                `json:"errors,omitempty"`
}

// ParserRuntime executes ParserSpec definitions deterministically.
type ParserRuntime struct{}

// NewParserRuntime creates a new ParserRuntime instance.
func NewParserRuntime() *ParserRuntime {
	return &ParserRuntime{}
}

// CanHandle evaluates whether a parser spec matches a raw event payload.
func (r *ParserRuntime) CanHandle(raw []byte, spec *ParserSpec) bool {
	if spec == nil || len(raw) == 0 {
		return false
	}
	rawStr := string(raw)

	// Format signature check
	switch spec.Match.Format {
	case "syslog":
		trimmed := strings.TrimSpace(rawStr)
		if !strings.HasPrefix(trimmed, "<") {
			return false
		}
	case "json":
		trimmed := strings.TrimSpace(rawStr)
		if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
			return false
		}
	case "cef":
		if !strings.HasPrefix(strings.TrimSpace(rawStr), "CEF:") {
			return false
		}
	case "leef":
		if !strings.HasPrefix(strings.TrimSpace(rawStr), "LEEF:") {
			return false
		}
	case "key_value":
		if !strings.Contains(rawStr, "=") {
			return false
		}
	case "csv":
		delim := spec.BodyParser.Delimiter
		if delim == "" {
			delim = ","
		}
		if !strings.Contains(rawStr, delim) {
			return false
		}
	}

	// Body tokens check
	for _, substr := range spec.Match.BodyContains {
		if !strings.Contains(rawStr, substr) {
			return false
		}
	}

	return true
}

// Parse executes the declarative ParserSpec on raw telemetry input.
func (r *ParserRuntime) Parse(raw []byte, spec *ParserSpec) (*ParseResult, error) {
	start := time.Now()

	if spec == nil {
		return nil, fmt.Errorf("spec cannot be nil")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("raw event bytes cannot be empty")
	}

	rawStr := string(raw)
	res := &ParseResult{
		Extracted:     make(map[string]interface{}),
		UnknownFields: make(map[string]interface{}),
		Lineage:       make(map[string]FieldLineage),
		Raw:           rawStr, // Non-negotiable: 100% raw byte retention
	}

	// Step 1: Intermediate extraction based on body_parser.type
	rawFields := make(map[string]interface{})
	var err error

	switch spec.BodyParser.Type {
	case "key_value":
		pairSep := spec.BodyParser.PairSeparator
		if pairSep == "" {
			pairSep = " "
		}
		kvSep := spec.BodyParser.KeyValueSeparator
		if kvSep == "" {
			kvSep = "="
		}

		if spec.Match.Format == "syslog" && strings.HasPrefix(strings.TrimSpace(rawStr), "<") {
			syslogMeta, body := ParseSyslog(rawStr)
			for k, v := range syslogMeta {
				rawFields[k] = v
			}
			bodyKV := ParseKeyValue(body, pairSep, kvSep)
			for k, v := range bodyKV {
				rawFields[k] = v
			}
		} else {
			rawFields = ParseKeyValue(rawStr, pairSep, kvSep)
		}

	case "json":
		rawFields, err = ParseJSON(rawStr)
		if err != nil {
			return nil, fmt.Errorf("JSON parse error: %w", err)
		}

	case "cef":
		rawFields, err = ParseCEF(rawStr)
		if err != nil {
			return nil, fmt.Errorf("CEF parse error: %w", err)
		}

	case "leef":
		rawFields, err = ParseLEEF(rawStr)
		if err != nil {
			return nil, fmt.Errorf("LEEF parse error: %w", err)
		}

	case "syslog":
		syslogMeta, body := ParseSyslog(rawStr)
		for k, v := range syslogMeta {
			rawFields[k] = v
		}
		rawFields["message"] = body

	case "csv":
		rawFields, err = ParseCSV(rawStr, spec.BodyParser.Delimiter, spec.BodyParser.Headers)
		if err != nil {
			return nil, fmt.Errorf("CSV parse error: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported body_parser.type %q", spec.BodyParser.Type)
	}

	// Step 2: Field transformation & canonical mapping
	mappedKeys := make(map[string]bool)

	for srcField, fieldSpec := range spec.Fields {
		val, found := rawFields[srcField]
		if !found {
			// Case-insensitive fallback
			for k, v := range rawFields {
				if strings.EqualFold(k, srcField) {
					val = v
					found = true
					srcField = k
					break
				}
			}
		}

		if !found {
			continue
		}

		mappedKeys[srcField] = true
		curVal := val

		// Apply transformations in declared sequence
		for _, op := range fieldSpec.Transformations {
			switch op {
			case "trim":
				curVal, _ = TransformTrim(curVal)
			case "lowercase":
				curVal, _ = TransformLowercase(curVal)
			case "uppercase":
				curVal, _ = TransformUppercase(curVal)
			case "enum_map":
				if len(fieldSpec.Enum) > 0 {
					curVal, _ = TransformEnumMap(curVal, fieldSpec.Enum)
				}
			case "integer":
				if i, err := TransformInteger(curVal); err == nil {
					curVal = i
				}
			case "float":
				if f, err := TransformFloat(curVal); err == nil {
					curVal = f
				}
			case "boolean":
				if b, err := TransformBoolean(curVal); err == nil {
					curVal = b
				}
			case "ip":
				if ip, err := TransformIP(curVal); err == nil {
					curVal = ip
				}
			case "timestamp":
				if ts, err := TransformTimestamp(curVal); err == nil {
					curVal = ts
				}
			}
		}

		// Apply final type coercion
		var typedVal interface{}
		var typeErr error

		switch fieldSpec.Type {
		case "string":
			if len(fieldSpec.Enum) > 0 {
				typedVal, _ = TransformEnumMap(curVal, fieldSpec.Enum)
			} else {
				typedVal = fmt.Sprintf("%v", curVal)
			}
		case "integer":
			typedVal, typeErr = TransformInteger(curVal)
		case "float":
			typedVal, typeErr = TransformFloat(curVal)
		case "boolean":
			typedVal, typeErr = TransformBoolean(curVal)
		case "ip":
			typedVal, typeErr = TransformIP(curVal)
		case "timestamp":
			typedVal, typeErr = TransformTimestamp(curVal)
		default:
			typedVal = curVal
		}

		if typeErr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("field %q type conversion error: %v", srcField, typeErr))
			continue
		}

		res.Extracted[fieldSpec.MapTo] = typedVal
		res.Lineage[fieldSpec.MapTo] = FieldLineage{
			SourceField: srcField,
			Rule:        fieldSpec.Type,
			Confidence:  1.0,
		}
	}

	// Step 3: Unknown fields preservation policy
	if spec.UnknownFields.Policy == "preserve" {
		for k, v := range rawFields {
			if !mappedKeys[k] {
				res.UnknownFields[k] = v
			}
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}
