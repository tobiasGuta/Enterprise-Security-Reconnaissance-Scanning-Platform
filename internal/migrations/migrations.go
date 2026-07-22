package migrations

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed sql/*.sql
var files embed.FS

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func Up(ctx context.Context, db DB) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return fmt.Errorf("migration %s has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("acquire migration lock: %w", err)
		}
		var applied bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if applied {
			tx.Rollback(ctx)
			continue
		}
		body, err := files.ReadFile("sql/" + entry.Name())
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, version, entry.Name()); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func Versions() ([]string, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
