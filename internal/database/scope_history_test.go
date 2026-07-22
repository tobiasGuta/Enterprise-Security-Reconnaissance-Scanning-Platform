package database

import (
	"reflect"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestScopeChangeClassifiesExpansionAndContraction(t *testing.T) {
	expanded := scopeChange("old-plan", []string{"i1"}, []string{"e1"}, domain.ScopeSnapshot{TargetPlanDigest: "expanded", IncludeRuleDigests: []string{"i1", "i2"}, ExcludeRuleDigests: []string{}})
	if !expanded.Changed || !expanded.ExpandsScope {
		t.Fatalf("expected expansion: %#v", expanded)
	}
	if !reflect.DeepEqual(expanded.AddedIncludeDigests, []string{"i2"}) || !reflect.DeepEqual(expanded.RemovedExcludeDigests, []string{"e1"}) {
		t.Fatalf("wrong diff: %#v", expanded)
	}
	contracted := scopeChange("old-plan", []string{"i1", "i2"}, []string{}, domain.ScopeSnapshot{TargetPlanDigest: "contracted", IncludeRuleDigests: []string{"i1"}, ExcludeRuleDigests: []string{"e1"}})
	if !contracted.Changed || contracted.ExpandsScope {
		t.Fatalf("contraction misclassified: %#v", contracted)
	}
}

func TestNormalizeScopeSnapshotSlicesForPostgresNotNullArrays(t *testing.T) {
	snapshot := domain.ScopeSnapshot{}
	normalizeScopeSnapshotSlices(&snapshot)
	values := [][]string{snapshot.IncludeRuleDigests, snapshot.ExcludeRuleDigests, snapshot.AddedIncludeDigests, snapshot.RemovedIncludeDigests, snapshot.AddedExcludeDigests, snapshot.RemovedExcludeDigests}
	for i, value := range values {
		if value == nil || len(value) != 0 {
			t.Fatalf("slice %d not normalized: %#v", i, value)
		}
	}
}
