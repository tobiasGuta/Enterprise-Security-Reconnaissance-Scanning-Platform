package artifact

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

func TestLocalArtifactLineageDigestAndRedaction(t *testing.T) {
	store, err := NewLocal(t.TempDir(), redaction.New())
	if err != nil {
		t.Fatal(err)
	}
	req := PutRequest{ProgramID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), ToolRunID: domain.NewID(), Type: "log", ContentType: "text/plain", Name: "tool.log", Data: []byte("Authorization: Bearer secret-value")}
	a, err := store.Put(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.Size == 0 || len(a.SHA256) != 64 || a.RedactionState != "redacted" {
		t.Fatalf("bad metadata: %#v", a)
	}
	b, err := os.ReadFile(a.StorageLocation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-value") {
		t.Fatal("artifact leaked secret")
	}
}
func TestLocalArtifactRequiresLineage(t *testing.T) {
	store, _ := NewLocal(t.TempDir(), nil)
	if _, err := store.Put(context.Background(), PutRequest{Name: "x"}); err == nil {
		t.Fatal("missing lineage accepted")
	}
}
