package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	uuid     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexID    = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	date     = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z?)?$`)
	objectID = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
)

type EndpointKey struct {
	ExactURL        string   `json:"exact_url"`
	RouteSignature  string   `json:"route_signature"`
	Method          string   `json:"method"`
	ContentType     string   `json:"content_type"`
	QueryParameters []string `json:"query_parameters"`
	Digest          string   `json:"digest"`
}

func URL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + strings.TrimPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("URL has no host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Fragment = ""
	u.Path = path.Clean("/" + strings.TrimPrefix(u.EscapedPath(), "/"))
	if u.Path == "/." {
		u.Path = "/"
	}
	u.RawPath = ""
	u.RawQuery = u.Query().Encode()
	return u.String(), nil
}

func Endpoint(rawURL, method, contentType string) (EndpointKey, error) {
	exact, err := URL(rawURL)
	if err != nil {
		return EndpointKey{}, err
	}
	u, _ := url.Parse(exact)
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	sig := route(u.Path)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	material := strings.Join([]string{u.Scheme, u.Host, sig, method, contentType, strings.Join(names, ",")}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return EndpointKey{ExactURL: exact, RouteSignature: sig, Method: method, ContentType: contentType, QueryParameters: names, Digest: hex.EncodeToString(sum[:])}, nil
}
func route(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		return "/"
	}
	for i, s := range segs {
		if dynamic(s) {
			segs[i] = "{id}"
		}
	}
	return "/" + strings.Join(segs, "/")
}
func dynamic(s string) bool {
	decoded, err := url.PathUnescape(s)
	if err == nil {
		s = decoded
	}
	if uuid.MatchString(s) || objectID.MatchString(s) || hexID.MatchString(s) || date.MatchString(s) {
		return true
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
		return true
	}
	if len(s) >= 16 {
		classes := 0
		if regexp.MustCompile(`[a-z]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[A-Z]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[0-9]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[-_]`).MatchString(s) {
			classes++
		}
		return classes >= 3
	}
	return false
}
