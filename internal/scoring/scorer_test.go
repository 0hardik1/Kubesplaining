package scoring

import (
	"math"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestComposeDefaultsZeroFactorsToOne(t *testing.T) {
	got := Compose(Factors{Base: 7.0})
	if got != 7.0 {
		t.Fatalf("Compose default factors: want 7.0, got %v", got)
	}
}

func TestComposeMultipliesAndAddsChainModifier(t *testing.T) {
	got := Compose(Factors{
		Base:           3.0,
		Exploitability: 1.2,
		BlastRadius:    1.5,
		ChainModifier:  2.0,
	})
	want := 3.0*1.2*1.5 + 2.0
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("Compose: want %v, got %v", want, got)
	}
}

func TestComposeClampsToTen(t *testing.T) {
	got := Compose(Factors{Base: 9.0, Exploitability: 1.5, BlastRadius: 1.2, ChainModifier: 5.0})
	if got != 10 {
		t.Fatalf("Compose clamp: want 10, got %v", got)
	}
}

func TestComposeClampsToZero(t *testing.T) {
	got := Compose(Factors{Base: -5, ChainModifier: -1})
	if got != 0 {
		t.Fatalf("Compose clamp low: want 0, got %v", got)
	}
}

func TestChainModifierBySeverity(t *testing.T) {
	cases := []struct {
		sev  models.Severity
		want float64
	}{
		{models.SeverityCritical, 2.0},
		{models.SeverityHigh, 1.0},
		{models.SeverityMedium, 0},
		{models.SeverityLow, 0},
		{models.SeverityInfo, 0},
		{"", 0},
	}
	for _, tc := range cases {
		if got := ChainModifier(tc.sev); got != tc.want {
			t.Errorf("ChainModifier(%q): want %v, got %v", tc.sev, tc.want, got)
		}
	}
}
