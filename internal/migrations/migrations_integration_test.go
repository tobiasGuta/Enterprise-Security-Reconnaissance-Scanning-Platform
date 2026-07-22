package migrations

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMigrationsAreIdempotent(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	versions, err := Versions()
	if err != nil {
		t.Fatal(err)
	}
	if count < len(versions) {
		t.Fatalf("applied=%d embedded=%d", count, len(versions))
	}
}
