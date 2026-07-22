package redaction

import (
	"net/url"
	"regexp"
	"strings"
)

type Redactor struct {
	secretNames map[string]struct{}
	patterns    []*regexp.Regexp
}

func New(extraNames ...string) *Redactor {
	r := &Redactor{secretNames: map[string]struct{}{}, patterns: []*regexp.Regexp{
		regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)([^\s,;]+(?:\s+[^\s,;]+)?)`),
		regexp.MustCompile(`(?i)((?:api[_-]?key|token|password|secret|cookie)\s*[:=]\s*)["']?([^\s,"';]+)`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		regexp.MustCompile(`(?i)https://hooks\.(?:slack|discord)[^\s]+`),
	}}
	for _, n := range append([]string{"authorization", "cookie", "set-cookie", "api_key", "apikey", "access_token", "refresh_token", "password", "secret", "signature"}, extraNames...) {
		r.secretNames[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	return r
}

func (r *Redactor) Text(s string) string {
	for _, p := range r.patterns {
		s = p.ReplaceAllString(s, "${1}<redacted>")
	}
	return r.redactURL(s)
}
func (r *Redactor) Headers(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if _, ok := r.secretNames[strings.ToLower(k)]; ok {
			out[k] = []string{"<redacted>"}
		} else {
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}
func (r *Redactor) redactURL(s string) string {
	lines := strings.Split(s, "\n")
	for lineIndex, line := range lines {
		fields := strings.Fields(line)
		for i, f := range fields {
			u, err := url.Parse(strings.Trim(f, "\"'(),"))
			if err != nil || u.Scheme == "" {
				continue
			}
			q := u.Query()
			changed := false
			for k := range q {
				if _, ok := r.secretNames[strings.ToLower(k)]; ok {
					q.Set(k, "<redacted>")
					changed = true
				}
			}
			if changed {
				u.RawQuery = q.Encode()
				fields[i] = u.String()
			}
		}
		lines[lineIndex] = strings.Join(fields, " ")
	}
	return strings.Join(lines, "\n")
}
