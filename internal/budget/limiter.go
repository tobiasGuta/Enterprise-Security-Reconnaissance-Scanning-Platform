package budget

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type Limits struct {
	Program  int
	Provider int
	Host     int
}

type Request struct {
	ProgramID domain.ID
	Provider  string
	Hosts     []string
}

type Limiter interface {
	Acquire(context.Context, Request) (release func(), err error)
}

type Local struct {
	mu        sync.Mutex
	limits    Limits
	programs  map[domain.ID]int
	providers map[string]int
	hosts     map[string]int
	changed   chan struct{}
}

func NewLocal(limits Limits) *Local {
	limits.Program = positive(limits.Program)
	limits.Provider = positive(limits.Provider)
	limits.Host = positive(limits.Host)
	return &Local{
		limits:    limits,
		programs:  map[domain.ID]int{},
		providers: map[string]int{},
		hosts:     map[string]int{},
		changed:   make(chan struct{}),
	}
}

func (l *Local) Acquire(ctx context.Context, request Request) (func(), error) {
	request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
	request.Hosts = normalized(request.Hosts)
	for {
		l.mu.Lock()
		if l.available(request) {
			l.programs[request.ProgramID]++
			if request.Provider != "" {
				l.providers[request.Provider]++
			}
			for _, host := range request.Hosts {
				l.hosts[host]++
			}
			released := false
			release := func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				if released {
					return
				}
				released = true
				decrement(l.programs, request.ProgramID)
				if request.Provider != "" {
					decrement(l.providers, request.Provider)
				}
				for _, host := range request.Hosts {
					decrement(l.hosts, host)
				}
				close(l.changed)
				l.changed = make(chan struct{})
			}
			l.mu.Unlock()
			return release, nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (l *Local) available(request Request) bool {
	if l.programs[request.ProgramID] >= l.limits.Program {
		return false
	}
	if request.Provider != "" && l.providers[request.Provider] >= l.limits.Provider {
		return false
	}
	for _, host := range request.Hosts {
		if l.hosts[host] >= l.limits.Host {
			return false
		}
	}
	return true
}

func HostsFromInput(raw json.RawMessage) []string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	var candidates []string
	collectCandidates(value, "", &candidates)
	hosts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if host := hostFromCandidate(candidate); host != "" {
			hosts = append(hosts, host)
		}
	}
	return normalized(hosts)
}

func collectCandidates(value any, key string, out *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			collectCandidates(child, strings.ToLower(childKey), out)
		}
	case []any:
		if targetKey(key) {
			for _, item := range typed {
				if text, ok := item.(string); ok {
					*out = append(*out, text)
				}
			}
		}
	case string:
		if targetKey(key) {
			*out = append(*out, typed)
		}
	}
}

func targetKey(key string) bool {
	switch key {
	case "target", "targets", "url", "urls", "domain", "domains", "host", "hosts", "exact_urls", "discovered_urls", "port_targets":
		return true
	default:
		return false
	}
}

func hostFromCandidate(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	if parsed, err := url.Parse(candidate); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		return strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
	}
	if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil {
		return strings.ToLower(ip.String())
	}
	if !strings.ContainsAny(candidate, "/?# ") {
		return strings.ToLower(strings.TrimSuffix(candidate, "."))
	}
	return ""
}

func normalized(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func decrement[K comparable](values map[K]int, key K) {
	if values[key] <= 1 {
		delete(values, key)
		return
	}
	values[key]--
}

func positive(value int) int {
	if value < 1 {
		return 1
	}
	return value
}
