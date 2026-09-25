package detectioncontracts

import (
	"fmt"
	"math"
)

// DPSReport summarizes the Detection Preservation Score and mandatory gate compliance.
type DPSReport struct {
	TotalEvaluated     int                `json:"total_evaluated"`
	TotalExpected      int                `json:"total_expected"`
	PreservedExpected  int                `json:"preserved_expected"`
	DPS                float64            `json:"dps"` // 0.0 to 1.0
	MandatoryTotal     int                `json:"mandatory_total"`
	MandatoryPreserved int                `json:"mandatory_preserved"`
	MandatoryPassed    bool               `json:"mandatory_passed"` // true iff MandatoryPreserved == MandatoryTotal (100%)
	Certified          bool               `json:"certified"`        // true iff MandatoryPassed && DPS >= MinDPS
	Violations         []EvaluationResult `json:"violations"`
}

// DPSCalculator computes detection preservation metrics adhering to Stage 13 assurance rules.
type DPSCalculator struct {
	MinDPS float64 // Configurable pass threshold for overall score (default 0.95)
}

// NewDPSCalculator creates a DPS calculator with default threshold.
func NewDPSCalculator() *DPSCalculator {
	return &DPSCalculator{
		MinDPS: 0.95,
	}
}

// Calculate computes the Detection Preservation Score from a series of rule evaluations.
// It strictly enforces:
// 1. Mandatory critical fixtures DPS must equal 100% (MandatoryPassed = true).
// 2. A critical failure can NEVER be averaged away by high scores on optional rules.
func (c *DPSCalculator) Calculate(results []EvaluationResult) (DPSReport, error) {
	if len(results) == 0 {
		return DPSReport{}, fmt.Errorf("no evaluation results provided to calculate DPS")
	}

	totalExpected := 0
	preservedExpected := 0
	mandatoryTotal := 0
	mandatoryPreserved := 0
	var violations []EvaluationResult

	for _, res := range results {
		totalExpected++
		if res.Preserved {
			preservedExpected++
		} else {
			violations = append(violations, res)
		}

		if res.IsMandatory {
			mandatoryTotal++
			if res.Preserved {
				mandatoryPreserved++
			}
		}
	}

	dps := float64(preservedExpected) / float64(totalExpected)
	// Round to 4 decimal places
	dps = math.Round(dps*10000) / 10000

	// Mandatory rules must be 100% preserved
	mandatoryPassed := (mandatoryTotal == 0) || (mandatoryPreserved == mandatoryTotal)

	// Certified requires mandatoryPassed and overall DPS >= MinDPS
	certified := mandatoryPassed && (dps >= c.MinDPS)

	return DPSReport{
		TotalEvaluated:     len(results),
		TotalExpected:      totalExpected,
		PreservedExpected:  preservedExpected,
		DPS:                dps,
		MandatoryTotal:     mandatoryTotal,
		MandatoryPreserved: mandatoryPreserved,
		MandatoryPassed:    mandatoryPassed,
		Certified:          certified,
		Violations:         violations,
	}, nil
}
