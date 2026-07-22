package provideroutput

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Kind string

const (
	HostRecord Kind = "host"
	PortRecord Kind = "port"
	URLRecord  Kind = "url"
)

type Record struct {
	Provider     string         `json:"provider"`
	Kind         Kind           `json:"kind"`
	Target       string         `json:"target"`
	Host         string         `json:"host,omitempty"`
	Port         int            `json:"port,omitempty"`
	StatusCode   int            `json:"status_code,omitempty"`
	Technologies []string       `json:"technologies,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
}

type Warning struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

type Batch struct {
	Records  []Record  `json:"records"`
	Warnings []Warning `json:"warnings"`
}

func Parse(provider string, lines []string) Batch {
	batch := Batch{Records: []Record{}, Warnings: []Warning{}}
	for i, line := range lines {
		record, err := parseOne(strings.ToLower(provider), strings.TrimSpace(line))
		if err != nil {
			batch.Warnings = append(batch.Warnings, Warning{Line: i + 1, Reason: err.Error()})
			continue
		}
		batch.Records = append(batch.Records, record)
	}
	return batch
}

func parseOne(provider, line string) (Record, error) {
	if line == "" {
		return Record{}, fmt.Errorf("empty record")
	}
	switch provider {
	case "subfinder", "chaos":
		return hostRecord(provider, plainOrStringField(line, "host", "name", "domain"))
	case "dnsx":
		return hostRecord(provider, plainOrStringField(line, "host", "input", "name"))
	case "naabu":
		return parseNaabu(line)
	case "httpx":
		return parseURLJSON(provider, line, "url", "final-url", "input")
	case "katana":
		return parseKatana(line)
	case "gau":
		return parseURLJSON(provider, line, "url")
	case "nuclei":
		return parseURLJSON(provider, line, "matched-at", "matched", "url")
	default:
		return Record{}, fmt.Errorf("unsupported provider adapter %q", provider)
	}
}

func hostRecord(provider, raw string) (Record, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if net.ParseIP(host) == nil {
		if len(host) == 0 || strings.ContainsAny(host, " /:@") {
			return Record{}, fmt.Errorf("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" {
				return Record{}, fmt.Errorf("invalid hostname")
			}
		}
	}
	return Record{Provider: provider, Kind: HostRecord, Target: host, Host: host}, nil
}

func parseNaabu(line string) (Record, error) {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) == nil {
		host := firstString(v, "host", "ip", "input")
		port := firstInt(v, "port")
		if host == "" || port == 0 {
			return Record{}, fmt.Errorf("naabu record requires host and port")
		}
		return portObservation("naabu", host, port, v)
	}
	host, rawPort, ok := strings.Cut(line, ":")
	if !ok {
		return Record{}, fmt.Errorf("invalid naabu record")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return Record{}, fmt.Errorf("invalid naabu port")
	}
	return portObservation("naabu", host, port, nil)
}

func portObservation(provider, host string, port int, fields map[string]any) (Record, error) {
	h, err := hostRecord(provider, host)
	if err != nil {
		return Record{}, err
	}
	if port < 1 || port > 65535 {
		return Record{}, fmt.Errorf("invalid port")
	}
	return Record{Provider: provider, Kind: PortRecord, Target: net.JoinHostPort(h.Host, strconv.Itoa(port)), Host: h.Host, Port: port, Fields: fields}, nil
}

func parseKatana(line string) (Record, error) {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) != nil {
		return parseURLValue("katana", line, nil)
	}
	raw := firstString(v, "url", "endpoint")
	if request, ok := v["request"].(map[string]any); ok && raw == "" {
		raw = firstString(request, "endpoint", "url")
	}
	return parseURLValue("katana", raw, v)
}

func parseURLJSON(provider, line string, keys ...string) (Record, error) {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) == nil {
		raw := firstString(v, keys...)
		if raw == "" && provider == "httpx" {
			host, scheme := firstString(v, "host", "input"), firstString(v, "scheme")
			if scheme != "" && host != "" {
				raw = scheme + "://" + host
			}
		}
		record, err := parseURLValue(provider, raw, v)
		if err == nil {
			record.StatusCode = firstInt(v, "status_code", "status-code", "status")
			record.Technologies = stringSlice(v["tech"])
			if len(record.Technologies) == 0 {
				record.Technologies = stringSlice(v["technologies"])
			}
		}
		return record, err
	}
	return parseURLValue(provider, line, nil)
}

func parseURLValue(provider, raw string, fields map[string]any) (Record, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Record{}, fmt.Errorf("invalid HTTP URL")
	}
	u.Fragment = ""
	return Record{Provider: provider, Kind: URLRecord, Target: u.String(), Host: strings.ToLower(u.Hostname()), Fields: fields}, nil
}

func plainOrStringField(line string, keys ...string) string {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) == nil {
		return firstString(v, keys...)
	}
	return line
}
func firstString(v map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := v[key].(string); ok {
			return s
		}
	}
	return ""
}
func firstInt(v map[string]any, keys ...string) int {
	for _, key := range keys {
		switch n := v[key].(type) {
		case float64:
			return int(n)
		case json.Number:
			value, _ := strconv.Atoi(n.String())
			return value
		case string:
			value, _ := strconv.Atoi(n)
			return value
		}
	}
	return 0
}
func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
