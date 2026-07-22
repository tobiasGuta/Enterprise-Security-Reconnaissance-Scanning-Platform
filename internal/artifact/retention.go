package artifact

import (
	"context"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type Deleter interface {
	Delete(context.Context, domain.Artifact) error
}

type RetentionStore interface {
	ExpiredArtifacts(context.Context, int) ([]domain.Artifact, error)
	DeleteArtifact(context.Context, domain.ID) error
}

// PurgeExpired removes expired content before deleting its metadata. Both
// operations are idempotent so an interrupted collection pass can be retried.
func PurgeExpired(ctx context.Context, store RetentionStore, storage Deleter, limit int) (int, error) {
	if store == nil || storage == nil {
		return 0, fmt.Errorf("retention store and artifact deleter are required")
	}
	if limit < 1 {
		return 0, fmt.Errorf("retention purge limit must be positive")
	}
	items, err := store.ExpiredArtifacts(ctx, limit)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, item := range items {
		if err := storage.Delete(ctx, item); err != nil {
			return removed, fmt.Errorf("delete artifact content %s: %w", item.ID, err)
		}
		if err := store.DeleteArtifact(ctx, item.ID); err != nil {
			return removed, fmt.Errorf("delete artifact metadata %s: %w", item.ID, err)
		}
		removed++
	}
	return removed, nil
}
