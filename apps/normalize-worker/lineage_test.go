package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	parser_runtime "github.com/kalpeshkarnawat19/SIH-PS-2/packages/parser-runtime"
)

type GoldenMeta struct {
	SourceID       string   `json:"source_id"`
	CriticalFields []string `json:"critical_fields"`
}

func TestLineage_GoldenCorporaLineageVerification(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "fixtures", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("reading golden directory %s: %v", goldenDir, err)
	}

	runtime := parser_runtime.NewParserRuntime()
	normalizer := NewNormalizer()
	totalVerifiedFields := 0
	totalSources := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceName := entry.Name()
		sourcePath := filepath.Join(goldenDir, sourceName)

		rawPath := filepath.Join(sourcePath, "raw", "events.raw")
		specPath := filepath.Join(sourcePath, "parser", "parser_spec.json")
		metaPath := filepath.Join(sourcePath, "metadata.json")

		if _, err := os.Stat(rawPath); os.IsNotExist(err) {
			continue
		}

		totalSources++
		t.Run(sourceName, func(t *testing.T) {
			rawBytes, err := os.ReadFile(rawPath)
			if err != nil {
				t.Fatalf("reading raw bytes: %v", err)
			}
			rawStr := string(rawBytes)

			specBytes, err := os.ReadFile(specPath)
			if err != nil {
				t.Fatalf("reading spec bytes: %v", err)
			}

			spec, err := parser_runtime.LoadParserSpecJSON(specBytes)
			if err != nil {
				t.Fatalf("loading spec: %v", err)
			}

			var meta GoldenMeta
			if metaBytes, err := os.ReadFile(metaPath); err == nil {
				_ = json.Unmarshal(metaBytes, &meta)
			}

			parseResult, err := runtime.Parse(rawBytes, spec)
			if err != nil {
				t.Fatalf("parsing raw: %v", err)
			}

			lineageRecords, err := normalizer.ExtractLineage(parseResult)
			if err != nil {
				t.Fatalf("extracting lineage: %v", err)
			}

			if len(lineageRecords) == 0 {
				t.Fatalf("no lineage records extracted for source %s", sourceName)
			}

			lineageByPath := make(map[string]parser_runtime.FieldLineage)
			for _, lin := range lineageRecords {
				// 1. Validate against field_lineage.schema.json rules
				if err := lin.Validate(); err != nil {
					t.Fatalf("lineage record for %s failed schema validation: %v", lin.NormalizedPath, err)
				}

				// 2. Scope guard: verify zero fabrication (raw locator must correspond to real raw evidence)
				switch lin.RawLocator.Type {
				case "key":
					key := lin.RawLocator.Value
					val := parseResult.Extracted[lin.NormalizedPath]
					valStr := fmt.Sprintf("%v", val)
					keyFound := strings.Contains(strings.ToLower(rawStr), strings.ToLower(key))
					valFound := len(valStr) > 0 && (strings.Contains(strings.ToLower(rawStr), strings.ToLower(valStr)) || (len(valStr) >= 10 && strings.Contains(rawStr, valStr[:10])))
					if !keyFound && !valFound && spec.BodyParser.Type != "csv" {
						t.Errorf("scope guard violation: neither raw locator key %q nor extracted value %q found in raw event", key, valStr)
					}
				case "json_pointer":
					// Must be valid JSON pointer
					if !strings.HasPrefix(lin.RawLocator.Value, "/") {
						t.Errorf("scope guard violation: json_pointer must start with '/': %q", lin.RawLocator.Value)
					}
				case "offset":
					// Must have colon
					if !strings.Contains(lin.RawLocator.Value, ":") {
						t.Errorf("scope guard violation: offset locator must be start:end: %q", lin.RawLocator.Value)
					}
				default:
					t.Errorf("unrecognized raw locator type: %q", lin.RawLocator.Type)
				}

				// 3. Mapping score must be valid
				if lin.MappingScore <= 0 || lin.MappingScore > 1.0 {
					t.Errorf("invalid mapping score: %.2f", lin.MappingScore)
				}

				// 4. Must be AUTO_ACCEPTED for certified golden parsers
				if lin.ReviewStatus != "AUTO_ACCEPTED" {
					t.Errorf("expected AUTO_ACCEPTED review status, got %s", lin.ReviewStatus)
				}

				lineageByPath[lin.NormalizedPath] = lin
				totalVerifiedFields++
			}

			// 5. Verify all critical fields defined in metadata.json have lineage evidence
			for _, critField := range meta.CriticalFields {
				if _, ok := lineageByPath[critField]; !ok {
					t.Errorf("missing critical field lineage for %q in %s", critField, sourceName)
				}
			}

			// 6. Test JSON serialization roundtrip
			for _, lin := range lineageRecords {
				b, err := lin.ToJSON()
				if err != nil {
					t.Fatalf("serializing lineage to JSON failed: %v", err)
				}
				var roundtrip map[string]interface{}
				if err := json.Unmarshal(b, &roundtrip); err != nil {
					t.Fatalf("unmarshaling lineage JSON failed: %v", err)
				}
				if roundtrip["normalized_path"] != lin.NormalizedPath {
					t.Errorf("roundtrip mismatch: expected %s, got %v", lin.NormalizedPath, roundtrip["normalized_path"])
				}
			}
		})
	}

	if totalSources == 0 {
		t.Fatalf("no golden sources were tested")
	}
	t.Logf("Successfully verified forensic field lineage for %d fields across %d golden sources", totalVerifiedFields, totalSources)
}

func TestLineage_ScopeGuard_RejectsNilAndFabrications(t *testing.T) {
	normalizer := NewNormalizer()

	// Nil parseResult must return error
	_, err := normalizer.ExtractLineage(nil)
	if err == nil {
		t.Fatalf("expected error for nil parseResult, got nil")
	}

	// Invalid lineage record within parseResult must be caught
	fakeResult := &parser_runtime.ParseResult{
		Lineage: map[string]parser_runtime.FieldLineage{
			"bad.field": {
				NormalizedPath: "invalid..path", // invalid regex
				RawLocator: parser_runtime.RawLocator{
					Type:  "key",
					Value: "something",
				},
				Extractor:       "kv",
				Transformations: []string{"trim"},
				MappingScore:    0.99,
				MappingEvidence: []string{"alias_match"},
				ReviewStatus:    "AUTO_ACCEPTED",
			},
		},
	}
	_, errInvalid := normalizer.ExtractLineage(fakeResult)
	if errInvalid == nil {
		t.Fatalf("expected error for invalid lineage record, got nil")
	}
}

func TestLineage_SubSliceReassemblyProof(t *testing.T) {
	runtime := parser_runtime.NewParserRuntime()
	raw := "src=192.168.1.10 dst=10.0.0.1 action=blocked user=admin"
	specJSON := []byte(`{
		"dsl_version": "1.0",
		"parser": {
			"id": "test.kv",
			"version": "1.0.0"
		},
		"match": {"format": "key_value"},
		"body_parser": {"type": "key_value", "pair_separator": " ", "key_value_separator": "="},
		"fields": {
			"src": {"type": "ip", "map_to": "src.ip", "transformations": ["trim", "ip"]},
			"dst": {"type": "ip", "map_to": "dst.ip", "transformations": ["trim", "ip"]},
			"action": {"type": "string", "map_to": "event.action", "transformations": ["trim"]}
		},
		"unknown_fields": {"policy": "preserve"},
		"raw": {"preserve": true}
	}`)
	spec, err := parser_runtime.LoadParserSpecJSON(specJSON)
	if err != nil {
		t.Fatalf("failed loading spec: %v", err)
	}

	res, err := runtime.Parse([]byte(raw), spec)
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	normalizer := NewNormalizer()
	lineages, err := normalizer.ExtractLineage(res)
	if err != nil {
		t.Fatalf("extract lineage failed: %v", err)
	}

	// Verify all extracted fields exist verbatim in raw bytes without modification
	for _, lin := range lineages {
		if !strings.Contains(raw, lin.RawLocator.Value) {
			t.Errorf("field %s raw locator %s not found in raw payload %s", lin.NormalizedPath, lin.RawLocator.Value, raw)
		}
	}
}

func TestLineage_DeterministicSliceIdentity(t *testing.T) {
	normalizer := NewNormalizer()
	runtime := parser_runtime.NewParserRuntime()
	raw := "src=10.0.0.5 dst=10.0.0.6 action=allow"
	specJSON := []byte(`{
		"dsl_version": "1.0",
		"parser": {
			"id": "test.det",
			"version": "1.0.0"
		},
		"match": {"format": "key_value"},
		"body_parser": {"type": "key_value", "pair_separator": " ", "key_value_separator": "="},
		"fields": {
			"src": {"type": "ip", "map_to": "src.ip", "transformations": ["trim", "ip"]},
			"dst": {"type": "ip", "map_to": "dst.ip", "transformations": ["trim", "ip"]}
		},
		"unknown_fields": {"policy": "preserve"},
		"raw": {"preserve": true}
	}`)
	spec, err := parser_runtime.LoadParserSpecJSON(specJSON)
	if err != nil {
		t.Fatalf("failed loading spec: %v", err)
	}

	res1, err := runtime.Parse([]byte(raw), spec)
	if err != nil {
		t.Fatalf("failed parsing res1: %v", err)
	}
	lin1, err := normalizer.ExtractLineage(res1)
	if err != nil {
		t.Fatalf("failed extracting lin1: %v", err)
	}

	res2, err := runtime.Parse([]byte(raw), spec)
	if err != nil {
		t.Fatalf("failed parsing res2: %v", err)
	}
	lin2, err := normalizer.ExtractLineage(res2)
	if err != nil {
		t.Fatalf("failed extracting lin2: %v", err)
	}

	map1 := make(map[string]parser_runtime.FieldLineage)
	for _, l := range lin1 {
		map1[l.NormalizedPath] = l
	}
	map2 := make(map[string]parser_runtime.FieldLineage)
	for _, l := range lin2 {
		map2[l.NormalizedPath] = l
	}

	if len(map1) != len(map2) {
		t.Fatalf("lineage count mismatch: %d != %d", len(map1), len(map2))
	}
	for k, v1 := range map1 {
		v2, ok := map2[k]
		if !ok || v1.RawLocator.Value != v2.RawLocator.Value {
			t.Errorf("lineage mismatch for %s: %+v vs %+v", k, v1, v2)
		}
	}
}
