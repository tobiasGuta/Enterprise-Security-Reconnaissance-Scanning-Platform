package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/queue"
)

type fakeStore struct {
	snapshot database.ConsoleSnapshot
	decided  string
}

func (f *fakeStore) ConsoleSnapshot(context.Context, domain.ID) (database.ConsoleSnapshot, error) {
	return f.snapshot, nil
}

func (f *fakeStore) DecideApproval(_ context.Context, _ domain.ID, decision, _ string) error {
	f.decided = decision
	return nil
}

type fakeQueue struct {
	retried string
	dead    []redis.XMessage
}

func (f *fakeQueue) Pending(context.Context) (*redis.XPending, error) {
	return &redis.XPending{Count: 3}, nil
}

func (f *fakeQueue) DeadLetters(context.Context, int64) ([]redis.XMessage, error) {
	return f.dead, nil
}

func (f *fakeQueue) RetryDeadLetter(_ context.Context, id string) error {
	f.retried = id
	return nil
}

func TestSnapshotSanitizesDeadLetterPayload(t *testing.T) {
	job := queue.Job{ID: "job-1", Provider: "nuclei", Attempt: 4, Action: domain.ActionRequest{Capability: "scan.nuclei", Input: json.RawMessage(`{"target":"https://secret.example.test","authorization":"secret"}`)}}
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	workQueue := &fakeQueue{dead: []redis.XMessage{{ID: "1-0", Values: map[string]any{"payload": string(payload), "error": "permanent_provider_failure", "failed_at": "2026-07-22T12:00:00Z"}}}}
	recorder := httptest.NewRecorder()
	New(&fakeStore{}, workQueue).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, forbidden := range []string{"secret.example.test", "authorization", `\"scope_includes\"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response exposed dead-letter payload field %q: %s", forbidden, body)
		}
	}
	for _, expected := range []string{"scan.nuclei", "nuclei", "permanent_provider_failure"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("response missing sanitized field %q: %s", expected, body)
		}
	}
}

func TestApprovalRequiresOperatorHeader(t *testing.T) {
	store := &fakeStore{}
	handler := New(store, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-1/decision", strings.NewReader(`{"decision":"approved"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if store.decided != "" {
		t.Fatalf("decision unexpectedly persisted: %s", store.decided)
	}
}

func TestApprovalAcceptsSameOriginOperatorRequest(t *testing.T) {
	store := &fakeStore{}
	handler := New(store, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8088/api/v1/approvals/approval-1/decision", strings.NewReader(`{"decision":"approved","actor":"alice"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Reconductor-Request", "operator-console")
	request.Header.Set("Origin", "http://127.0.0.1:8088")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.decided != "approved" {
		t.Fatalf("decision = %q", store.decided)
	}
}

func TestStaticConsoleHasSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	New(&fakeStore{}, nil).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing restrictive CSP: %q", recorder.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(recorder.Body.String(), "Reconductor Console") {
		t.Fatal("console shell was not served")
	}
}
