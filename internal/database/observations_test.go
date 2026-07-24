package database

import (
	"encoding/json"
	"testing"
)

func TestObservationLinesPreferAuthorizedStructuredRecords(t *testing.T) {
	raw := json.RawMessage(`{"lines":["https://inside.test/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"https://inside.test/","status_code":401}],"records":[{"provider":"httpx","kind":"url","target":"https://outside.test/"}]}`)
	lines := observationLines(raw)
	if len(lines) != 1 || extractValue(lines[0]) != "https://inside.test/" {
		t.Fatalf("authorized observations=%q", lines)
	}
	if json.Valid(json.RawMessage(lines[0])) == false {
		t.Fatalf("structured observation was not retained: %q", lines[0])
	}
}

func TestObservationLinesFallsBackToLegacyLines(t *testing.T) {
	lines := observationLines(json.RawMessage(`{"lines":["https://legacy.test/"]}`))
	if len(lines) != 1 || lines[0] != "https://legacy.test/" {
		t.Fatalf("legacy observations=%q", lines)
	}
}
