package assets

import (
	"encoding/json"
	"reflect"
	"sort"
)

type State struct {
	Type             string          `json:"type"`
	Value            string          `json:"value"`
	SourceCapability string          `json:"source_capability"`
	Metadata         json.RawMessage `json:"metadata"`
}
type Coverage struct {
	Capability string `json:"capability"`
	Successful bool   `json:"successful"`
	Complete   bool   `json:"complete"`
}
type Change struct {
	Kind      string `json:"kind"`
	AssetType string `json:"asset_type"`
	Value     string `json:"value"`
	Before    *State `json:"before,omitempty"`
	After     *State `json:"after,omitempty"`
	Reason    string `json:"reason"`
}

func Compare(previous, current []State, coverage []Coverage) []Change {
	prev := index(previous)
	cur := index(current)
	covered := map[string]bool{}
	for _, c := range coverage {
		covered[c.Capability] = c.Successful && c.Complete
	}
	var out []Change
	for k, now := range cur {
		old, ok := prev[k]
		if !ok {
			n := now
			out = append(out, Change{Kind: "new", AssetType: now.Type, Value: now.Value, After: &n})
			continue
		}
		if !sameMetadata(old.Metadata, now.Metadata) {
			o, n := old, now
			out = append(out, Change{Kind: "changed", AssetType: now.Type, Value: now.Value, Before: &o, After: &n})
		}
	}
	for k, old := range prev {
		if _, ok := cur[k]; ok {
			continue
		}
		if !covered[old.SourceCapability] {
			continue
		}
		o := old
		out = append(out, Change{Kind: "removed", AssetType: old.Type, Value: old.Value, Before: &o, Reason: "source step completed successfully with complete coverage"})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Value < out[j].Value
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
func index(states []State) map[string]State {
	out := map[string]State{}
	for _, s := range states {
		out[s.Type+"\x00"+s.Value] = s
	}
	return out
}
func sameMetadata(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return string(a) == string(b)
	}
	return reflect.DeepEqual(x, y)
}
