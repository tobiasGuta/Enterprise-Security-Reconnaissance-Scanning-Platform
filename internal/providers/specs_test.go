package providers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerDockerfilePinsMatchProviderSpecifications(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "worker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(dockerfile)
	wants := []string{
		"ARG SUBFINDER_VERSION=" + SubfinderPinnedVersion,
		"ARG CHAOS_VERSION=" + ChaosPinnedVersion,
		"ARG DNSX_VERSION=" + DNSxPinnedVersion,
		"ARG NAABU_VERSION=" + NaabuPinnedVersion,
		"ARG HTTPX_VERSION=" + HTTPXPinnedVersion,
		"ARG KATANA_VERSION=" + KatanaPinnedVersion,
		"ARG GAU_VERSION=" + GAUPinnedVersion,
		"ARG PROVIDER_GO_IMAGE=golang:1.26-alpine",
		"ARG NUCLEI_IMAGE=projectdiscovery/nuclei:" + NucleiPinnedVersion,
		"ARG NUCLEI_TEMPLATES_VERSION=" + TemplatesPinnedVersion,
	}
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("worker Dockerfile is missing %q", want)
		}
	}
	marker, err := os.ReadFile(filepath.Join("..", "..", "worker", "nuclei-templates.version"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(marker)) != TemplatesPinnedVersion {
		t.Fatalf("template marker=%q want=%q", strings.TrimSpace(string(marker)), TemplatesPinnedVersion)
	}
}
