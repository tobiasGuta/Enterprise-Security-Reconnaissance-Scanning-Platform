package artifact

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type retentionFake struct {
	items       []domain.Artifact
	deletedFile []domain.ID
	deletedRow  []domain.ID
	fileErr     error
}

func (f *retentionFake) ExpiredArtifacts(context.Context, int) ([]domain.Artifact, error) {
	return f.items, nil
}
func (f *retentionFake) Delete(_ context.Context, item domain.Artifact) error {
	f.deletedFile = append(f.deletedFile, item.ID)
	return f.fileErr
}
func (f *retentionFake) DeleteArtifact(_ context.Context, id domain.ID) error {
	f.deletedRow = append(f.deletedRow, id)
	return nil
}

func TestPurgeExpiredDeletesContentBeforeMetadata(t *testing.T) {
	fake := &retentionFake{items: []domain.Artifact{{ID: "expired"}}}
	removed, err := PurgeExpired(context.Background(), fake, fake, 10)
	if err != nil || removed != 1 || len(fake.deletedFile) != 1 || len(fake.deletedRow) != 1 {
		t.Fatalf("removed=%d err=%v files=%v rows=%v", removed, err, fake.deletedFile, fake.deletedRow)
	}
}

func TestPurgeExpiredDoesNotDropMetadataWhenContentDeletionFails(t *testing.T) {
	fake := &retentionFake{items: []domain.Artifact{{ID: "expired"}}, fileErr: errors.New("storage unavailable")}
	if _, err := PurgeExpired(context.Background(), fake, fake, 10); err == nil {
		t.Fatal("content deletion failure was ignored")
	}
	if len(fake.deletedRow) != 0 {
		t.Fatalf("metadata deleted before content: %v", fake.deletedRow)
	}
}

func TestLocalPutAppliesRetentionExpiry(t *testing.T) {
	store, err := NewLocal(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(30 * time.Minute)
	a, err := store.Put(context.Background(), PutRequest{ProgramID: "program", TaskID: "task", WorkflowRunID: "run", StepRunID: "step", ToolRunID: "tool", Name: "result.json", Retention: time.Hour, Data: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	if a.ExpiresAt == nil || a.ExpiresAt.Before(before) {
		t.Fatalf("expiry=%v", a.ExpiresAt)
	}
	if err := store.Delete(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.StorageLocation); !os.IsNotExist(err) {
		t.Fatalf("artifact still exists: %v", err)
	}
}
