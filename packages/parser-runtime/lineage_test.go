package parser_runtime

import (
	"testing"
)

func TestLineageValidation_Valid(t *testing.T) {
	valid := &FieldLineage{
		NormalizedPath: "src.ip",
		RawLocator: RawLocator{
			Type:  "key",
			Value: "src",
		},
		Extractor:       "kv",
		Transformations: []string{"trim", "ip"},
		MappingScore:    0.99,
		MappingEvidence: []string{"alias_match", "type_match", "event_family_context"},
		ReviewStatus:    "AUTO_ACCEPTED",
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid lineage, got error: %v", err)
	}

	data, err := valid.ToJSON()
	if err != nil {
		t.Fatalf("serialization failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("serialized data is empty")
	}
}

func TestLineageValidation_InvalidCases(t *testing.T) {
	base := func() FieldLineage {
		return FieldLineage{
			NormalizedPath: "src.ip",
			RawLocator: RawLocator{
				Type:  "key",
				Value: "src",
			},
			Extractor:       "kv",
			Transformations: []string{"trim", "ip"},
			MappingScore:    1.0,
			MappingEvidence: []string{"type_match"},
			ReviewStatus:    "AUTO_ACCEPTED",
		}
	}

	// Bad normalized path
	badPath := base()
	badPath.NormalizedPath = "123.invalid-path"
	if err := badPath.Validate(); err == nil {
		t.Errorf("expected error for invalid normalized_path")
	}

	// Bad raw locator type
	badLocatorType := base()
	badLocatorType.RawLocator.Type = "magic_guess"
	if err := badLocatorType.Validate(); err == nil {
		t.Errorf("expected error for invalid raw locator type")
	}

	// Empty raw locator value
	emptyLocatorVal := base()
	emptyLocatorVal.RawLocator.Value = ""
	if err := emptyLocatorVal.Validate(); err == nil {
		t.Errorf("expected error for empty raw locator value")
	}

	// Invalid extractor
	badExtractor := base()
	badExtractor.Extractor = "python_eval"
	if err := badExtractor.Validate(); err == nil {
		t.Errorf("expected error for unapproved extractor")
	}

	// Invalid transformation
	badTransform := base()
	badTransform.Transformations = []string{"arbitrary_exec"}
	if err := badTransform.Validate(); err == nil {
		t.Errorf("expected error for unapproved transformation")
	}

	// Out of bounds mapping score
	badScore := base()
	badScore.MappingScore = 1.5
	if err := badScore.Validate(); err == nil {
		t.Errorf("expected error for score > 1.0")
	}

	// Empty mapping evidence
	emptyEvidence := base()
	emptyEvidence.MappingEvidence = []string{}
	if err := emptyEvidence.Validate(); err == nil {
		t.Errorf("expected error for empty mapping evidence")
	}

	// Bad review status
	badStatus := base()
	badStatus.ReviewStatus = "PROBABLY_OK"
	if err := badStatus.Validate(); err == nil {
		t.Errorf("expected error for invalid review status")
	}
}

func TestLineage_FindRawByteOffset_ExactAndScopeGuard(t *testing.T) {
	raw := []byte("src=192.168.1.50 dst=10.0.0.1 action=block")

	// Exact token found
	start, end, found := FindRawByteOffset(raw, "192.168.1.50")
	if !found {
		t.Fatalf("expected token to be found in raw bytes")
	}
	if string(raw[start:end]) != "192.168.1.50" {
		t.Errorf("offset span mismatch: got %q, expected 192.168.1.50", string(raw[start:end]))
	}

	// Scope guard: zero fabrication for missing token
	_, _, foundMissing := FindRawByteOffset(raw, "non_existent_token_999")
	if foundMissing {
		t.Errorf("scope guard failure: fabricated offset for missing token")
	}

	// Empty raw / token
	_, _, foundEmpty := FindRawByteOffset(nil, "token")
	if foundEmpty {
		t.Errorf("expected not found for nil raw")
	}
}

func TestLineage_BuildFieldLineage_ScopeGuard_NoFabrication(t *testing.T) {
	raw := "src=10.0.0.1 dst=10.0.0.2 action=allow"

	// Existing field
	lin, err := BuildFieldLineage("src.ip", "src", "key_value", []string{"trim", "ip"}, raw, "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error building lineage: %v", err)
	}
	if lin.RawLocator.Value != "src" {
		t.Errorf("expected locator value 'src', got %q", lin.RawLocator.Value)
	}
	if lin.Extractor != "kv" {
		t.Errorf("expected extractor 'kv', got %q", lin.Extractor)
	}

	// Missing field with no evidence in raw: BuildFieldLineage must reject to prevent fabrication
	_, errMissing := BuildFieldLineage("user.name", "non_existent_key_xyz", "key_value", nil, raw, "alice")
	if errMissing == nil {
		t.Fatalf("scope guard violation: expected error when source field is missing from raw bytes, got nil")
	}
}
