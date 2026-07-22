package console

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/queue"
)

//go:embed static/*
var staticFiles embed.FS

type Store interface {
	ConsoleSnapshot(context.Context, domain.ID) (database.ConsoleSnapshot, error)
	DecideApproval(context.Context, domain.ID, string, string) error
}

type Queue interface {
	Pending(context.Context) (*redis.XPending, error)
	DeadLetters(context.Context, int64) ([]redis.XMessage, error)
	RetryDeadLetter(context.Context, string) error
}

type Server struct {
	store Store
	queue Queue
	mux   *http.ServeMux
}

type Snapshot struct {
	database.ConsoleSnapshot
	Queue QueueStatus `json:"queue"`
}

type QueueStatus struct {
	Pending     int64        `json:"pending"`
	DeadLetters []DeadLetter `json:"dead_letters"`
	Error       string       `json:"error,omitempty"`
}

type DeadLetter struct {
	MessageID  string    `json:"message_id"`
	JobID      domain.ID `json:"job_id,omitempty"`
	Capability string    `json:"capability,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Attempt    int       `json:"attempt"`
	Error      string    `json:"error"`
	FailedAt   string    `json:"failed_at"`
}

func New(store Store, workQueue Queue) http.Handler {
	s := &Server{store: store, queue: workQueue, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/v1/snapshot", s.snapshot)
	s.mux.HandleFunc("POST /api/v1/approvals/{id}/decision", s.decideApproval)
	s.mux.HandleFunc("POST /api/v1/dead-letters/{id}/retry", s.retryDeadLetter)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	assets := http.FileServer(http.FS(staticRoot))
	s.mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/styles.css" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		assets.ServeHTTP(w, r)
	}))
	return s.securityHeaders(s.mux)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ConsoleSnapshot(r.Context(), domain.ID(strings.TrimSpace(r.URL.Query().Get("program_id"))))
	if err != nil {
		slog.Error("operator console snapshot failed", "error", err)
		writeError(w, http.StatusInternalServerError, "console data is temporarily unavailable")
		return
	}
	out := Snapshot{ConsoleSnapshot: data, Queue: QueueStatus{DeadLetters: []DeadLetter{}}}
	if s.queue != nil {
		pending, pendingErr := s.queue.Pending(r.Context())
		messages, deadErr := s.queue.DeadLetters(r.Context(), 50)
		if pendingErr == nil && pending != nil {
			out.Queue.Pending = pending.Count
		}
		if deadErr == nil {
			out.Queue.DeadLetters = sanitizeDeadLetters(messages)
		}
		if pendingErr != nil || deadErr != nil {
			out.Queue.Error = "queue status unavailable"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Actor    string `json:"actor"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Decision = strings.ToLower(strings.TrimSpace(body.Decision))
	if body.Decision != "approved" && body.Decision != "rejected" {
		writeError(w, http.StatusBadRequest, "decision must be approved or rejected")
		return
	}
	body.Actor = strings.TrimSpace(body.Actor)
	if body.Actor == "" {
		body.Actor = "console-operator"
	}
	if len(body.Actor) > 80 {
		writeError(w, http.StatusBadRequest, "actor is too long")
		return
	}
	if err := s.store.DecideApproval(r.Context(), domain.ID(r.PathValue("id")), body.Decision, body.Actor); err != nil {
		slog.Warn("operator console approval failed", "approval_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusConflict, "approval is no longer pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Decision})
}

func (s *Server) retryDeadLetter(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if s.queue == nil {
		writeError(w, http.StatusServiceUnavailable, "queue status unavailable")
		return
	}
	if err := s.queue.RetryDeadLetter(r.Context(), r.PathValue("id")); err != nil {
		slog.Warn("operator console dead-letter retry failed", "message_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusConflict, "dead-letter job could not be retried")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func sanitizeDeadLetters(messages []redis.XMessage) []DeadLetter {
	out := make([]DeadLetter, 0, len(messages))
	for _, message := range messages {
		item := DeadLetter{MessageID: message.ID, Error: stringValue(message.Values["error"]), FailedAt: stringValue(message.Values["failed_at"])}
		raw := stringValue(message.Values["payload"])
		var job queue.Job
		if json.Unmarshal([]byte(raw), &job) == nil {
			item.JobID = job.ID
			item.Capability = job.Action.Capability
			item.Provider = job.Provider
			item.Attempt = job.Attempt
		}
		out = append(out, item)
	}
	return out
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func validOperatorRequest(r *http.Request) bool {
	if r.Header.Get("X-Reconductor-Request") != "operator-console" {
		return false
	}
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request body must be valid JSON")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSONStatus(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func HTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
