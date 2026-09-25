package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	parser_runtime "github.com/kalpeshkarnawat19/SIH-PS-2/packages/parser-runtime"
)

func TestCanonicalIR_GoldenCorpusParsersOutputValidIR(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "fixtures", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("reading golden directory %s: %v", goldenDir, err)
	}

	runtime := parser_runtime.NewParserRuntime()
	normalizer := NewNormalizer()
	testedCount := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceName := entry.Name()
		sourcePath := filepath.Join(goldenDir, sourceName)

		rawPath := filepath.Join(sourcePath, "raw", "events.raw")
		specPath := filepath.Join(sourcePath, "parser", "parser_spec.json")

		if _, err := os.Stat(rawPath); os.IsNotExist(err) {
			continue
		}

		testedCount++
		t.Run(sourceName, func(t *testing.T) {
			rawBytes, err := os.ReadFile(rawPath)
			if err != nil {
				t.Fatalf("reading %s: %v", rawPath, err)
			}

			specBytes, err := os.ReadFile(specPath)
			if err != nil {
				t.Fatalf("reading %s: %v", specPath, err)
			}

			spec, err := parser_runtime.LoadParserSpecJSON(specBytes)
			if err != nil {
				t.Fatalf("loading spec: %v", err)
			}

			parseResult, err := runtime.Parse(rawBytes, spec)
			if err != nil {
				t.Fatalf("parsing raw bytes: %v", err)
			}

			envInput := RawEnvelopeInput{
				EventID:   "01J9A0K0P0Z3R3M5WQ6F7H8J9K",
				SourceID:  sourceName,
				RawRef:    "raw/2026/09/17/" + sourceName + "/01J9A0K0P0Z3R3M5WQ6F7H8J9K",
				RawSHA256: "4a0a19218e082a343393b8bd810de8a39c8f7ff733e3ce81d89b3e056c1003fe",
				IngestTS:  "2026-09-17T12:00:00Z",
			}

			normEvent, err := normalizer.Normalize(envInput, parseResult, spec)
			if err != nil {
				t.Fatalf("normalizing event to Canonical IR failed: %v", err)
			}

			if err := normEvent.Validate(); err != nil {
				t.Fatalf("Canonical IR failed schema validation: %v", err)
			}

			// Verify required schema fields
			if normEvent.SchemaVersion != "1.0" {
				t.Errorf("expected schema_version 1.0, got %s", normEvent.SchemaVersion)
			}
			if normEvent.Event.Class == "" || normEvent.Event.Action == "" || normEvent.Event.Outcome == "" {
				t.Errorf("missing core event fields: %+v", normEvent.Event)
			}
			if normEvent.Raw.Ref != envInput.RawRef || normEvent.Raw.SHA256 != envInput.RawSHA256 {
				t.Errorf("raw provenance mismatch: expected ref=%s sha=%s", envInput.RawRef, envInput.RawSHA256)
			}
			if normEvent.Quality.Status != "VERIFIED" {
				t.Errorf("expected quality.status VERIFIED, got %s", normEvent.Quality.Status)
			}

			// Verify JSON serialization matches contract
			jsonBytes, err := normEvent.ToJSON()
			if err != nil {
				t.Fatalf("JSON serialization failed: %v", err)
			}

			var roundtrip map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &roundtrip); err != nil {
				t.Fatalf("roundtrip unmarshaling failed: %v", err)
			}
		})
	}

	if testedCount == 0 {
		t.Fatalf("no golden sources were tested for IR")
	}
	t.Logf("Successfully validated Canonical IR for all %d golden sources", testedCount)
}

func TestCanonicalIR_ScopeGuard_NoECSOrOCSFInternalTruth(t *testing.T) {
	// Build Guide Scope Guard: Do not use ECS/OCSF as internal source of truth.
	// Ensure no ECS/OCSF field namespaces leak into parser specs or Canonical IR structs.
	forbiddenNamespaces := []string{
		"ecs.version",
		"@timestamp",
		"activity_id",
		"class_uid",
		"category_uid",
		"type_uid",
	}

	goldenDir := filepath.Join("..", "..", "fixtures", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("reading golden directory %s: %v", goldenDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		specPath := filepath.Join(goldenDir, entry.Name(), "parser", "parser_spec.json")
		if _, err := os.Stat(specPath); os.IsNotExist(err) {
			continue
		}

		specBytes, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("reading %s: %v", specPath, err)
		}

		specStr := string(specBytes)
		for _, forbidden := range forbiddenNamespaces {
			if strings.Contains(specStr, forbidden) {
				t.Fatalf("scope guard violation in %s: parser spec leaks exporter field %q", specPath, forbidden)
			}
		}
	}
}

func TestCanonicalIR_ValidationRules(t *testing.T) {
	valid := &NormalizedEvent{
		SchemaVersion: "1.0",
		EventID:       "01J9A0K0P0Z3R3M5WQ6F7H8J9K",
		Event: EventInfo{
			Class:   "NETWORK_CONNECTION",
			Action:  "blocked",
			Outcome: "failure",
			Time:    "2026-09-17T12:00:00Z",
		},
		Source: SourceInfo{
			Vendor:   "Acme",
			Product:  "Firewall",
			DeviceID: "fw-01",
		},
		Src: &Endpoint{IP: "10.0.0.1", Port: 80},
		Dst: &Endpoint{IP: "192.168.1.1", Port: 443},
		Parser: ParserMetadata{
			ID:      "test.parser",
			Version: "1.0.0",
		},
		Raw: RawProvenance{
			Ref:    "raw/ref/123",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		Quality: QualityReport{
			MappingScore: 0.95,
			Status:       "VERIFIED",
		},
		Extensions: map[string]interface{}{},
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid IR, got error: %v", err)
	}

	// Invalid IP
	invalidIP := *valid
	invalidIP.Src = &Endpoint{IP: "999.999.999.999", Port: 80}
	if err := invalidIP.Validate(); err == nil {
		t.Errorf("expected error for invalid IP")
	}

	// Invalid outcome
	invalidOutcome := *valid
	invalidOutcome.Event.Outcome = "maybe"
	if err := invalidOutcome.Validate(); err == nil {
		t.Errorf("expected error for invalid outcome")
	}

	// Invalid schema version
	invalidSchema := *valid
	invalidSchema.SchemaVersion = "2.0"
	if err := invalidSchema.Validate(); err == nil {
		t.Errorf("expected error for invalid schema version")
	}
}
