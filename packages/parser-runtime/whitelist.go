package parser_runtime

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Allowed operations whitelist. Any operation not in this set is strictly rejected.
var whitelistedOperations = map[string]bool{
	"trim":          true,
	"lowercase":     true,
	"uppercase":     true,
	"integer":       true,
	"float":         true,
	"boolean":       true,
	"ip":            true,
	"timestamp":     true,
	"enum_map":      true,
	"split":         true,
	"join":          true,
	"substring":     true,
	"json_pointer":  true,
	"key_value":     true,
	"regex_capture": true,
	"cef_parse":     true,
	"leef_parse":    true,
	"syslog_parse":  true,
	"csv_parse":     true,
}

// IsWhitelistedOperation checks if an operation name is approved in the DSL.
func IsWhitelistedOperation(op string) bool {
	return whitelistedOperations[op]
}

// TransformTrim trims leading and trailing whitespace from strings.
func TransformTrim(val interface{}) (interface{}, error) {
	if s, ok := val.(string); ok {
		return strings.TrimSpace(s), nil
	}
	return val, nil
}

// TransformLowercase converts string values to lowercase.
func TransformLowercase(val interface{}) (interface{}, error) {
	if s, ok := val.(string); ok {
		return strings.ToLower(s), nil
	}
	return val, nil
}

// TransformUppercase converts string values to uppercase.
func TransformUppercase(val interface{}) (interface{}, error) {
	if s, ok := val.(string); ok {
		return strings.ToUpper(s), nil
	}
	return val, nil
}

// TransformInteger parses string or numeric input into an int64.
func TransformInteger(val interface{}) (int64, error) {
	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		clean := strings.TrimSpace(v)
		// Try decimal
		if i, err := strconv.ParseInt(clean, 10, 64); err == nil {
			return i, nil
		}
		// If float representation like "100.0"
		if f, err := strconv.ParseFloat(clean, 64); err == nil {
			return int64(f), nil
		}
		return 0, fmt.Errorf("cannot parse integer from %q", v)
	default:
		return 0, fmt.Errorf("unsupported type %T for integer", val)
	}
}

// TransformFloat parses string or numeric input into a float64.
func TransformFloat(val interface{}) (float64, error) {
	switch v := val.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case string:
		clean := strings.TrimSpace(v)
		f, err := strconv.ParseFloat(clean, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse float from %q: %w", v, err)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("unsupported type %T for float", val)
	}
}

// TransformBoolean parses input into a boolean.
func TransformBoolean(val interface{}) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case int, int64:
		return v != 0, nil
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		switch s {
		case "true", "t", "1", "yes", "y", "enable", "enabled", "allow", "allowed":
			return true, nil
		case "false", "f", "0", "no", "n", "disable", "disabled", "deny", "denied", "block", "blocked":
			return false, nil
		default:
			return false, fmt.Errorf("cannot parse boolean from %q", v)
		}
	default:
		return false, fmt.Errorf("unsupported type %T for boolean", val)
	}
}

// TransformIP validates and standardizes IPv4 or IPv6 address strings.
func TransformIP(val interface{}) (string, error) {
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("ip requires string input, got %T", val)
	}
	clean := strings.TrimSpace(s)
	ip := net.ParseIP(clean)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address format: %q", s)
	}
	return ip.String(), nil
}

// Common timestamp formats for log ingestion
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05Z",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
	"Jan 02 15:04:05",
	"Jan  2 15:04:05",
	"Jan 02 15:04:05 2006",
	"Jan  2 15:04:05 2006",
	time.RFC1123,
	time.RFC1123Z,
}

// TransformTimestamp parses various timestamp layouts and Unix timestamps to standard RFC3339 UTC.
func TransformTimestamp(val interface{}) (string, error) {
	switch v := val.(type) {
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano), nil
	case int64:
		// Check if seconds, milliseconds, or nanoseconds
		if v > 1e18 { // nanoseconds
			return time.Unix(0, v).UTC().Format(time.RFC3339Nano), nil
		} else if v > 1e11 { // milliseconds
			return time.Unix(v/1000, (v%1000)*1e6).UTC().Format(time.RFC3339), nil
		}
		// seconds
		return time.Unix(v, 0).UTC().Format(time.RFC3339), nil
	case float64:
		sec := int64(v)
		nsec := int64((v - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC().Format(time.RFC3339), nil
	case string:
		clean := strings.TrimSpace(v)
		// Check if string of digits
		if num, err := strconv.ParseInt(clean, 10, 64); err == nil {
			return TransformTimestamp(num)
		}
		for _, layout := range timestampLayouts {
			if t, err := time.Parse(layout, clean); err == nil {
				// If year was not specified (e.g. syslog format "Oct 11 22:14:15"), use current year
				if t.Year() == 0 {
					t = t.AddDate(time.Now().Year(), 0, 0)
				}
				return t.UTC().Format(time.RFC3339), nil
			}
		}
		return "", fmt.Errorf("unable to parse timestamp from string %q", v)
	default:
		return "", fmt.Errorf("unsupported type %T for timestamp", val)
	}
}

// TransformEnumMap translates a categorical input string via a lookup map.
func TransformEnumMap(val interface{}, enumMap map[string]string) (interface{}, error) {
	s := fmt.Sprintf("%v", val)
	if target, exists := enumMap[s]; exists {
		return target, nil
	}
	// Case-insensitive fallback
	sLower := strings.ToLower(s)
	for k, v := range enumMap {
		if strings.ToLower(k) == sLower {
			return v, nil
		}
	}
	return val, nil
}

// ParseKeyValue parses raw key-value tokens into a map.
// Handles unquoted values, single-quoted values, and double-quoted values.
func ParseKeyValue(input string, pairSep, kvSep string) map[string]interface{} {
	if pairSep == "" {
		pairSep = " "
	}
	if kvSep == "" {
		kvSep = "="
	}

	result := make(map[string]interface{})
	runes := []rune(input)
	n := len(runes)
	i := 0

	for i < n {
		// Skip pair separators and whitespace
		for i < n && (strings.ContainsRune(pairSep, runes[i]) || runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		// Read key
		keyStart := i
		for i < n && runes[i] != rune(kvSep[0]) && !strings.ContainsRune(pairSep, runes[i]) {
			i++
		}
		if i >= n || runes[i] != rune(kvSep[0]) {
			break
		}
		key := strings.TrimSpace(string(runes[keyStart:i]))
		i++ // skip kv separator

		// Read value
		var val string
		if i < n && (runes[i] == '"' || runes[i] == '\'') {
			quote := runes[i]
			i++
			valStart := i
			for i < n && runes[i] != quote {
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			val = string(runes[valStart:i])
			if i < n && runes[i] == quote {
				i++
			}
		} else {
			valStart := i
			for i < n && !strings.ContainsRune(pairSep, runes[i]) {
				i++
			}
			val = strings.TrimSpace(string(runes[valStart:i]))
		}

		if key != "" {
			result[key] = val
		}
	}

	return result
}

// SyslogRFC5424Pattern parses RFC 5424 formatted syslog.
var syslog5424Regex = regexp.MustCompile(`^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[(.*?)\]|-)\s*(.*)$`)

// SyslogRFC3164Pattern parses legacy BSD RFC 3164 syslog.
var syslog3164Regex = regexp.MustCompile(`^<(\d+)>([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$`)

// ParseSyslog decomposes a syslog message into header metadata and body.
func ParseSyslog(raw string) (map[string]interface{}, string) {
	fields := make(map[string]interface{})
	trimmed := strings.TrimSpace(raw)

	// Try RFC 5424
	if matches := syslog5424Regex.FindStringSubmatch(trimmed); len(matches) > 0 {
		pri, _ := strconv.Atoi(matches[1])
		version, _ := strconv.Atoi(matches[2])
		fields["prival"] = pri
		fields["facility"] = pri / 8
		fields["severity"] = pri % 8
		fields["syslog_version"] = version
		fields["timestamp"] = matches[3]
		fields["hostname"] = matches[4]
		fields["app_name"] = matches[5]
		fields["proc_id"] = matches[6]
		fields["msg_id"] = matches[7]
		if matches[8] != "" {
			fields["structured_data"] = matches[8]
		}
		body := matches[9]
		return fields, body
	}

	// Try RFC 3164
	if matches := syslog3164Regex.FindStringSubmatch(trimmed); len(matches) > 0 {
		pri, _ := strconv.Atoi(matches[1])
		fields["prival"] = pri
		fields["facility"] = pri / 8
		fields["severity"] = pri % 8
		fields["timestamp"] = matches[2]
		fields["hostname"] = matches[3]
		fields["app_name"] = matches[4]
		if matches[5] != "" {
			fields["proc_id"] = matches[5]
		}
		body := matches[6]
		return fields, body
	}

	// Fallback: check leading <PRI>
	if strings.HasPrefix(trimmed, "<") {
		if endIdx := strings.Index(trimmed, ">"); endIdx > 0 && endIdx <= 4 {
			if pri, err := strconv.Atoi(trimmed[1:endIdx]); err == nil {
				fields["prival"] = pri
				fields["facility"] = pri / 8
				fields["severity"] = pri % 8
				return fields, strings.TrimSpace(trimmed[endIdx+1:])
			}
		}
	}

	return fields, trimmed
}

// ParseCEF parses ArcSight Common Event Format.
// CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassID|Name|Severity|[Extension]
func ParseCEF(raw string) (map[string]interface{}, error) {
	fields := make(map[string]interface{})
	trimmed := strings.TrimSpace(raw)

	if !strings.HasPrefix(trimmed, "CEF:") {
		return nil, fmt.Errorf("not a valid CEF message: missing CEF: prefix")
	}

	content := trimmed[4:]
	// Parse 7 pipe-delimited header fields, respecting escaped pipes \|
	var parts []string
	var cur strings.Builder
	runes := []rune(content)
	n := len(runes)

	for i := 0; i < n; i++ {
		if len(parts) == 7 {
			cur.WriteString(string(runes[i:]))
			break
		}
		if runes[i] == '\\' && i+1 < n && runes[i+1] == '|' {
			cur.WriteRune('|')
			i++
			continue
		}
		if runes[i] == '|' {
			parts = append(parts, cur.String())
			cur.Reset()
		} else {
			cur.WriteRune(runes[i])
		}
	}
	if cur.Len() > 0 || len(parts) < 7 {
		parts = append(parts, cur.String())
	}

	if len(parts) < 7 {
		return nil, fmt.Errorf("malformed CEF message: expected 7 header fields, got %d", len(parts))
	}

	version, _ := strconv.Atoi(parts[0])
	fields["cef_version"] = version
	fields["device_vendor"] = parts[1]
	fields["device_product"] = parts[2]
	fields["device_version"] = parts[3]
	fields["device_event_class_id"] = parts[4]
	fields["name"] = parts[5]
	fields["severity"] = parts[6]

	if len(parts) >= 8 && strings.TrimSpace(parts[7]) != "" {
		kv := ParseKeyValue(parts[7], " ", "=")
		for k, v := range kv {
			fields[k] = v
		}
	}

	return fields, nil
}

// ParseLEEF parses Log Event Extended Format (LEEF 1.0 and 2.0).
// LEEF:1.0|Vendor|Product|Version|EventID|[Extension]
// LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|[Extension]
func ParseLEEF(raw string) (map[string]interface{}, error) {
	fields := make(map[string]interface{})
	trimmed := strings.TrimSpace(raw)

	if !strings.HasPrefix(trimmed, "LEEF:") {
		return nil, fmt.Errorf("not a valid LEEF message: missing LEEF: prefix")
	}

	content := trimmed[5:]
	parts := strings.Split(content, "|")
	if len(parts) < 5 {
		return nil, fmt.Errorf("malformed LEEF message: expected at least 5 header fields, got %d", len(parts))
	}

	version := parts[0]
	fields["leef_version"] = version
	fields["vendor"] = parts[1]
	fields["product"] = parts[2]
	fields["version"] = parts[3]
	fields["event_id"] = parts[4]

	var extension string
	delimiter := "\t"

	if strings.HasPrefix(version, "2.0") {
		if len(parts) >= 6 {
			delimStr := parts[5]
			if delimStr == "x20" {
				delimiter = " "
			} else if delimStr == "x09" {
				delimiter = "\t"
			} else if len(delimStr) > 0 {
				delimiter = delimStr
			}
		}
		if len(parts) >= 7 {
			extension = strings.Join(parts[6:], "|")
		}
	} else {
		if len(parts) >= 6 {
			extension = strings.Join(parts[5:], "|")
		}
	}

	if extension != "" {
		kv := ParseKeyValue(extension, delimiter, "=")
		for k, v := range kv {
			fields[k] = v
		}
	}

	return fields, nil
}

// ParseJSON parses a JSON payload and flattens nested fields into dotted keys.
func ParseJSON(raw string) (map[string]interface{}, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	result := make(map[string]interface{})
	flattenJSON("", parsed, result)
	return result, nil
}

func flattenJSON(prefix string, src interface{}, dest map[string]interface{}) {
	switch v := src.(type) {
	case map[string]interface{}:
		for k, val := range v {
			nestedKey := k
			if prefix != "" {
				nestedKey = prefix + "." + k
			}
			dest[nestedKey] = val
			flattenJSON(nestedKey, val, dest)
		}
	}
}

// ParseCSV parses comma or custom delimiter separated values.
func ParseCSV(raw string, delimiter string, headers []string) (map[string]interface{}, error) {
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(raw)))
	if delimiter != "" && len(delimiter) == 1 {
		reader.Comma = rune(delimiter[0])
	}
	record, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV row: %w", err)
	}

	result := make(map[string]interface{})
	for i, val := range record {
		key := fmt.Sprintf("col%d", i)
		if i < len(headers) && headers[i] != "" {
			key = headers[i]
		}
		result[key] = val
	}
	return result, nil
}
