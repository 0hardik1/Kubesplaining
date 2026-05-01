// Package scoring centralizes the composite risk-score formula and the tiny helpers
// analyzers share for score clamping and severity thresholding.
//
// Composite formula (spec §8.3):
//
//	score = base × exploitability × blast_radius + chain_modifier
//
// Analyzers populate Factors (or a raw Score for legacy callers); the engine's
// post-run pass fills in ChainModifier from privilege-escalation paths and then
// calls Compose so ordering across modules is meaningful.
package scoring

import "github.com/0hardik1/kubesplaining/internal/models"

// Factors are the components of the composite risk score. Exploitability and BlastRadius
// default to 1.0 when unset; ChainModifier defaults to 0.0 and is filled in by the engine.
type Factors struct {
	Base           float64
	Exploitability float64
	BlastRadius    float64
	ChainModifier  float64
}

// Compose applies the composite formula and clamps the result to [0, 10].
// Zero-valued Exploitability or BlastRadius are treated as 1.0 so callers can leave them unset.
func Compose(f Factors) float64 {
	exp := f.Exploitability
	if exp == 0 {
		exp = 1
	}
	blast := f.BlastRadius
	if blast == 0 {
		blast = 1
	}
	return Clamp(f.Base*exp*blast + f.ChainModifier)
}

// SeverityForScore maps a numeric 0–10 score to the corresponding severity bucket.
func SeverityForScore(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score >= 2.0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// MinScoreForSeverity returns the lower bound of the score range for a severity bucket
// (the inverse of SeverityForScore boundaries). Used by the admission-aware reweight
// stage to snap an attenuated finding's score to the floor of its new severity bucket
// so Score and Severity stay consistent for downstream consumers.
func MinScoreForSeverity(s models.Severity) float64 {
	switch s {
	case models.SeverityCritical:
		return 9.0
	case models.SeverityHigh:
		return 7.0
	case models.SeverityMedium:
		return 4.0
	case models.SeverityLow:
		return 2.0
	default:
		return 0
	}
}

// ChainModifier returns the score bump to apply to a finding whose subject can reach
// a privilege-escalation sink of the given (highest) severity. Non-chain findings get 0.
func ChainModifier(highestReachable models.Severity) float64 {
	switch highestReachable {
	case models.SeverityCritical:
		return 2.0
	case models.SeverityHigh:
		return 1.0
	default:
		return 0
	}
}

// Clamp returns score bounded to [0, 10].
func Clamp(score float64) float64 {
	switch {
	case score < 0:
		return 0
	case score > 10:
		return 10
	default:
		return score
	}
}

// AboveThreshold reports whether a finding's severity meets or exceeds the given threshold, using Severity.Rank ordering.
func AboveThreshold(f models.Finding, threshold models.Severity) bool {
	return f.Severity.Rank() >= threshold.Rank()
}
