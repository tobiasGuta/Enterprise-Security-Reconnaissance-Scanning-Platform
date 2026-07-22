package providercheck

import (
	"context"
	"errors"
	"testing"
)

type fakeRunner struct {
	path, output string
	lookErr      error
	probeErr     error
}

func (f fakeRunner) LookPath(string) (string, error) { return f.path, f.lookErr }
func (f fakeRunner) CombinedOutput(context.Context, string, []string) (string, error) {
	return f.output, f.probeErr
}

func TestCheckClassifiesProviderAvailability(t *testing.T) {
	spec := Spec{Name: "httpx", DisplayName: "HTTPX", Executable: "httpx", ExecutableEnv: "HTTPX_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "1.", PinnedVersion: "v1.10.0", Required: true}
	tests := []struct {
		name   string
		runner fakeRunner
		want   Status
	}{
		{"missing", fakeRunner{lookErr: errors.New("not found")}, Missing},
		{"wrong binary", fakeRunner{path: "httpx", output: "Usage: httpx [OPTIONS]", probeErr: errors.New("exit 2")}, WrongBinary},
		{"unparseable", fakeRunner{path: "httpx", output: "http client"}, WrongBinary},
		{"incompatible", fakeRunner{path: "httpx", output: "Current Version: v2.0.0"}, Incompatible},
		{"renamed binary", fakeRunner{path: "dnsx.exe", output: "Current Version: v1.10.0"}, WrongBinary},
		{"compatible", fakeRunner{path: "httpx", output: "[INF] Current Version: v1.10.0"}, Compatible},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Check(context.Background(), spec, test.runner)
			if got.Status != test.want {
				t.Fatalf("status=%s result=%+v", got.Status, got)
			}
		})
	}
}

func TestEvaluateAcceptsTwoPartVersions(t *testing.T) {
	got := Evaluate(Spec{DisplayName: "GAU", CompatiblePrefix: "2."}, "gau version 2.2", nil)
	if got.Status != Compatible || got.DetectedVersion != "v2.2" {
		t.Fatalf("result=%+v", got)
	}
}

func TestEvaluateSanitizesDiagnosticOutput(t *testing.T) {
	got := Evaluate(Spec{DisplayName: "Katana", CompatiblePrefix: "1."}, "\x1b[31mfatal\x1b[0m\nsecond line", errors.New("exit 1"))
	if got.Status != WrongBinary || got.Details != "fatal second line" {
		t.Fatalf("result=%+v", got)
	}
}
