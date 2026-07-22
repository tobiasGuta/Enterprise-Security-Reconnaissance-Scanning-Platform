package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

type PutRequest struct {
	ProgramID, TaskID, WorkflowRunID, StepRunID, ToolRunID domain.ID
	Type, ContentType, Name                                string
	Sensitive                                              bool
	Retention                                              time.Duration
	Data                                                   []byte
}
type Storage interface {
	Put(context.Context, PutRequest) (domain.Artifact, error)
}
type Local struct {
	root     string
	redactor *redaction.Redactor
}

func NewLocal(root string, r *redaction.Redactor) (*Local, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = redaction.New()
	}
	return &Local{root: abs, redactor: r}, nil
}
func (l *Local) Put(_ context.Context, r PutRequest) (domain.Artifact, error) {
	if r.ProgramID == "" || r.TaskID == "" || r.WorkflowRunID == "" || r.StepRunID == "" || r.ToolRunID == "" {
		return domain.Artifact{}, fmt.Errorf("complete artifact lineage is required")
	}
	name := filepath.Base(r.Name)
	if name == "." || name == "" {
		name = "artifact.bin"
	}
	parts := []string{l.root, "programs", string(r.ProgramID), "tasks", string(r.TaskID), "runs", string(r.WorkflowRunID), "steps", string(r.StepRunID), "tool-runs", string(r.ToolRunID)}
	if r.Sensitive {
		parts = append(parts, "sensitive")
	}
	dir := filepath.Join(parts...)
	if !within(l.root, dir) {
		return domain.Artifact{}, fmt.Errorf("artifact path escapes storage root")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return domain.Artifact{}, err
	}
	data := r.Data
	state := "sensitive-separated"
	if !r.Sensitive {
		data = []byte(l.redactor.Text(string(data)))
		state = "redacted"
	}
	location := filepath.Join(dir, name)
	if err := os.WriteFile(location, data, 0600); err != nil {
		return domain.Artifact{}, err
	}
	sum := sha256.Sum256(data)
	created := time.Now().UTC()
	var expires *time.Time
	if r.Retention > 0 {
		value := created.Add(r.Retention)
		expires = &value
	}
	return domain.Artifact{ID: domain.NewID(), TaskID: r.TaskID, WorkflowRunID: r.WorkflowRunID, StepRunID: r.StepRunID, ToolRunID: r.ToolRunID, Type: r.Type, ContentType: r.ContentType, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), StorageLocation: location, CreatedAt: created, ExpiresAt: expires, RedactionState: state, Sensitive: r.Sensitive}, nil
}

func (l *Local) Delete(_ context.Context, a domain.Artifact) error {
	location, err := filepath.Abs(a.StorageLocation)
	if err != nil {
		return err
	}
	if !within(l.root, location) {
		return fmt.Errorf("artifact path escapes storage root")
	}
	err = os.Remove(location)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
