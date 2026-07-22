package assets

import (
	"encoding/json"
	"testing"
)

func TestChangeDetectionRequiresCompleteCoverageForRemoval(t *testing.T) {
	prev := []State{{Type: "host", Value: "old.example", SourceCapability: "discover.subdomains", Metadata: json.RawMessage(`{"ip":"1.1.1.1"}`)}, {Type: "host", Value: "same.example", SourceCapability: "discover.subdomains", Metadata: json.RawMessage(`{"ip":"1.1.1.1"}`)}}
	cur := []State{{Type: "host", Value: "same.example", SourceCapability: "discover.subdomains", Metadata: json.RawMessage(`{"ip":"2.2.2.2"}`)}, {Type: "host", Value: "new.example", SourceCapability: "discover.subdomains", Metadata: json.RawMessage(`{}`)}}
	changes := Compare(prev, cur, []Coverage{{Capability: "discover.subdomains", Successful: false, Complete: false}})
	if has(changes, "removed") {
		t.Fatal("incomplete scan produced removal")
	}
	changes = Compare(prev, cur, []Coverage{{Capability: "discover.subdomains", Successful: true, Complete: true}})
	if !has(changes, "removed") || !has(changes, "new") || !has(changes, "changed") {
		t.Fatalf("missing expected changes: %#v", changes)
	}
}
func has(c []Change, k string) bool {
	for _, v := range c {
		if v.Kind == k {
			return true
		}
	}
	return false
}
