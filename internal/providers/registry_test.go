package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
)

type testScope struct{}

func (testScope) Allows(string) bool { return true }
func TestCompareAssetsStatusRouting(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	r := Registry(cfg)
	input := json.RawMessage(`{"current":["{\"url\":\"https://x.test/ok\",\"status_code\":200}","{\"url\":\"https://x.test/login\",\"status_code\":403}","{\"url\":\"https://x.test/missing\",\"status_code\":404}"],"previous":[],"coverage_complete":true}`)
	result, err := r.Execute(context.Background(), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: testScope{}})
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Crawl  []string            `json:"crawl_targets"`
		Scan   []string            `json:"scan_targets"`
		Routes map[string][]string `json:"status_routes"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Crawl) != 1 || len(output.Scan) != 2 || len(output.Routes["ignored"]) != 1 {
		t.Fatalf("unexpected routes: %s", result.Action.Output)
	}
}

func TestDNSxInvocationUsesSortedDeduplicatedHostnameStdin(t *testing.T) {
	invocation, err := dnsxInvocation(commandprovider.Input{Targets: []string{"https://Z.Example.Test./path?q=1#fragment", "http://a.example.test:8080/other", "https://A.EXAMPLE.TEST/", "http://192.0.2.1/path", "https://[2001:db8::1]/v1"}}, policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(invocation.Args, " "), "-silent"; got != want {
		t.Fatalf("args=%q", got)
	}
	if strings.Contains(strings.Join(invocation.Args, " "), "-d") {
		t.Fatalf("dnsx received brute-force flag: %v", invocation.Args)
	}
	if got, want := string(invocation.Stdin), "192.0.2.1\n2001:db8::1\na.example.test\nz.example.test\n"; got != want {
		t.Fatalf("stdin=%q want=%q", got, want)
	}
}

func TestAuditedProviderFlagMatrix(t *testing.T) {
	input := commandprovider.Input{Domains: []string{"example.test"}, Targets: []string{"https://app.example.test/path"}, Ports: "80,443", Headless: true}
	recon := config.Recon{RateLimit: 75, Concurrency: 20}
	pol := policy.Policy{RateLimit: 20, Concurrency: 5}
	nuclei := config.Nuclei{RateLimit: 50, HostConcurrency: 10, TemplateConcurrency: 10, HeadlessConcurrency: 2, Severity: []string{"low", "medium", "high", "critical"}, IncludeTags: []string{"cve", "exposure", "misconfig"}, ExcludeTags: []string{"dos", "fuzz", "bruteforce", "intrusive"}, TemplateDirectory: `C:\nuclei-templates`}
	tests := []struct {
		name  string
		want  string
		build func() ([]string, error)
	}{
		{"subfinder", "-d example.test -silent", func() ([]string, error) { return subfinderArgs(input, pol) }},
		{"chaos", "-d example.test -silent", func() ([]string, error) { return chaosArgs(input, "configured") }},
		{"naabu", "-host app.example.test -silent -rate 20 -p 80,443", func() ([]string, error) { return naabuArgs(input, pol, recon) }},
		{"httpx", "-u https://app.example.test/path -silent -json -status-code -tech-detect -threads 5", func() ([]string, error) { return httpxArgs(input, pol, recon) }},
		{"katana", "-u https://app.example.test/path -silent -jsonl -fs fqdn -rate-limit 20 -concurrency 5 -headless", func() ([]string, error) { return katanaArgs(input, pol, recon) }},
		{"gau", "--json example.test", func() ([]string, error) { return gauArgs(input) }},
		{"nuclei", `-u https://app.example.test/path -jsonl -silent -dr -rl 20 -c 5 -bulk-size 5 -headc 2 -severity low,medium,high,critical -tags cve,exposure,misconfig -etags dos,fuzz,bruteforce,intrusive -t C:\nuclei-templates`, func() ([]string, error) { return nucleiArgs(input, pol, nuclei) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := test.build()
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(args, " "); got != test.want {
				t.Fatalf("args=%q want=%q", got, test.want)
			}
		})
	}
	invocation, err := dnsxInvocation(input, pol)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(invocation.Args, " "); got != "-silent" || string(invocation.Stdin) != "app.example.test\n" {
		t.Fatalf("dnsx args=%q stdin=%q", got, invocation.Stdin)
	}
}

func TestDNSxInvocationRejectsInvalidURLAndKeepsLargeListsOffCommandLine(t *testing.T) {
	if _, err := dnsxInvocation(commandprovider.Input{Targets: []string{"not-a-url"}}, policy.Policy{}); err == nil {
		t.Fatal("invalid URL accepted")
	}
	targets := make([]string, 5000)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://host-%04d.example.test/path", i)
	}
	invocation, err := dnsxInvocation(commandprovider.Input{Targets: targets}, policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(invocation.Args) != 1 || len(invocation.Stdin) < 100000 {
		t.Fatalf("large list was not transported through stdin: args=%d stdin=%d", len(invocation.Args), len(invocation.Stdin))
	}
}

type denyScope struct{}

func (denyScope) Allows(string) bool { return false }

func TestDNSxValidationStillRejectsOutOfScopeURLs(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilityImpl, ok := Registry(cfg).Get("resolve.dns")
	if !ok {
		t.Fatal("resolve.dns missing")
	}
	raw, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://outside.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{Capability: "resolve.dns", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"resolve.dns"}}, Scope: denyScope{}}
	if err := capabilityImpl.Validate(context.Background(), req); err == nil {
		t.Fatal("out-of-scope DNS target accepted")
	}
}
