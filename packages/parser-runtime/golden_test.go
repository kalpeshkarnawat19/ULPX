package parser_runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type ExpectedOutput struct {
	Extracted      map[string]interface{} `json:"extracted"`
	CriticalFields []string               `json:"critical_fields"`
	UnknownFields  map[string]interface{} `json:"unknown_fields"`
}

type GoldenMetadata struct {
	SourceID              string   `json:"source_id"`
	Format                string   `json:"format"`
	Description           string   `json:"description"`
	CriticalFields        []string `json:"critical_fields"`
	MinExtractionAccuracy float64  `json:"min_extraction_accuracy"`
	RequiresRawRetention  bool     `json:"requires_raw_retention"`
}

func TestGoldenCorpus(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "fixtures", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("reading golden directory %s: %v", goldenDir, err)
	}

	runtime := NewParserRuntime()
	totalFieldsEvaluated := 0
	totalFieldsMatched := 0
	totalCriticalFields := 0
	matchedCriticalFields := 0

	sourcesTested := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceName := entry.Name()
		sourcePath := filepath.Join(goldenDir, sourceName)

		rawPath := filepath.Join(sourcePath, "raw", "events.raw")
		specPath := filepath.Join(sourcePath, "parser", "parser_spec.json")
		expectedPath := filepath.Join(sourcePath, "expected", "events.json")
		metaPath := filepath.Join(sourcePath, "metadata.json")

		// Verify files exist
		if _, err := os.Stat(rawPath); os.IsNotExist(err) {
			continue
		}

		sourcesTested++
		t.Run(sourceName, func(t *testing.T) {
			rawBytes, err := os.ReadFile(rawPath)
			if err != nil {
				t.Fatalf("reading %s: %v", rawPath, err)
			}

			specBytes, err := os.ReadFile(specPath)
			if err != nil {
				t.Fatalf("reading %s: %v", specPath, err)
			}

			expectedBytes, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatalf("reading %s: %v", expectedPath, err)
			}

			metaBytes, err := os.ReadFile(metaPath)
			if err != nil {
				t.Fatalf("reading %s: %v", metaPath, err)
			}

			var expected ExpectedOutput
			if err := json.Unmarshal(expectedBytes, &expected); err != nil {
				t.Fatalf("unmarshaling expected: %v", err)
			}

			var meta GoldenMetadata
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				t.Fatalf("unmarshaling metadata: %v", err)
			}

			// Validate ParserSpec against DSL rules
			spec, err := LoadParserSpecJSON(specBytes)
			if err != nil {
				t.Fatalf("loading parser spec: %v", err)
			}

			// Execute parse
			res, err := runtime.Parse(rawBytes, spec)
			if err != nil {
				t.Fatalf("runtime parse error: %v", err)
			}

			// 1. Raw Retention Check (Non-negotiable 100%)
			if meta.RequiresRawRetention {
				if res.Raw != string(rawBytes) {
					t.Fatalf("raw retention failure: stored raw did not match input bytes")
				}
			}

			// 2. Critical Fields Check (Exit criterion: 100% correctness)
			criticalList := meta.CriticalFields
			if len(criticalList) == 0 {
				criticalList = expected.CriticalFields
			}

			for _, crit := range criticalList {
				totalCriticalFields++
				expVal, hasExp := expected.Extracted[crit]
				gotVal, hasGot := res.Extracted[crit]

				if !hasExp {
					t.Fatalf("critical field %q not defined in expected.json", crit)
				}
				if !hasGot {
					t.Fatalf("critical field %q missing from extracted output", crit)
				}

				if fmt.Sprintf("%v", expVal) != fmt.Sprintf("%v", gotVal) {
					t.Fatalf("critical field %q mismatch: expected %v (%T), got %v (%T)", crit, expVal, expVal, gotVal, gotVal)
				}
				matchedCriticalFields++
			}

			// 3. Overall Extraction Accuracy
			for expKey, expVal := range expected.Extracted {
				totalFieldsEvaluated++
				if gotVal, found := res.Extracted[expKey]; found {
					if fmt.Sprintf("%v", expVal) == fmt.Sprintf("%v", gotVal) {
						totalFieldsMatched++
					} else {
						t.Errorf("field %s mismatch: expected %v, got %v", expKey, expVal, gotVal)
					}
				} else {
					t.Errorf("expected field %s was not extracted", expKey)
				}
			}

			// 4. Unknown Fields Preservation Check
			for k, v := range expected.UnknownFields {
				if gotUnknown, found := res.UnknownFields[k]; found {
					if fmt.Sprintf("%v", v) != fmt.Sprintf("%v", gotUnknown) {
						t.Errorf("unknown field %s value mismatch: expected %v, got %v", k, v, gotUnknown)
					}
				} else {
					t.Errorf("expected unknown field %s was not preserved", k)
				}
			}
		})
	}

	if sourcesTested == 0 {
		t.Fatalf("no golden sources were tested")
	}

	// Exit Criteria Assertions
	accuracy := float64(totalFieldsMatched) / float64(totalFieldsEvaluated)
	t.Logf("Golden Corpus Extraction Accuracy: %.2f%% (%d/%d fields)", accuracy*100, totalFieldsMatched, totalFieldsEvaluated)

	if accuracy < 0.98 {
		t.Fatalf("extraction accuracy %.2f%% is below required threshold of 98.0%%", accuracy*100)
	}

	critAccuracy := float64(matchedCriticalFields) / float64(totalCriticalFields)
	t.Logf("Critical Field Correctness: %.2f%% (%d/%d critical fields)", critAccuracy*100, matchedCriticalFields, totalCriticalFields)

	if critAccuracy < 1.0 {
		t.Fatalf("critical field correctness %.2f%% is below required threshold of 100.0%%", critAccuracy*100)
	}
}
