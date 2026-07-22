package providercheck

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

type Status string

const (
	Compatible   Status = "compatible"
	Missing      Status = "missing"
	WrongBinary  Status = "wrong_binary"
	Incompatible Status = "incompatible"
)

type Spec struct {
	Name             string
	DisplayName      string
	Executable       string
	ExecutableEnv    string
	VersionArgs      []string
	CompatiblePrefix string
	PinnedVersion    string
	Required         bool
}

type Result struct {
	Component       string `json:"component"`
	Kind            string `json:"kind"`
	Required        bool   `json:"required"`
	Status          Status `json:"status"`
	DetectedVersion string `json:"detected_version,omitempty"`
	ExpectedVersion string `json:"expected_version,omitempty"`
	Path            string `json:"path,omitempty"`
	Details         string `json:"details,omitempty"`
}

type Runner interface {
	LookPath(string) (string, error)
	CombinedOutput(context.Context, string, []string) (string, error)
}

type OSRunner struct{}

func (OSRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (OSRunner) CombinedOutput(ctx context.Context, name string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

var versionPattern = regexp.MustCompile(`(?i)(?:^|[^0-9])v?(\d+\.\d+(?:\.\d+)?)(?:[^0-9]|$)`)
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func Check(ctx context.Context, spec Spec, runner Runner) Result {
	result := baseResult(spec)
	if runner == nil {
		runner = OSRunner{}
	}
	path, err := runner.LookPath(spec.Executable)
	if err != nil {
		result.Status = Missing
		result.Details = fmt.Sprintf("configure %s with the executable path", spec.ExecutableEnv)
		return result
	}
	result.Path = path
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, probeErr := runner.CombinedOutput(probeCtx, path, spec.VersionArgs)
	if probeCtx.Err() != nil {
		probeErr = probeCtx.Err()
	}
	evaluated := EvaluateExecutable(spec, path, output, probeErr)
	evaluated.Path = path
	return evaluated
}

func EvaluateExecutable(spec Spec, executable, output string, probeErr error) Result {
	result := Evaluate(spec, output, probeErr)
	if result.Status != Compatible {
		return result
	}
	base := strings.TrimSuffix(filepath.Base(executable), filepath.Ext(executable))
	if spec.Name != "" && !strings.EqualFold(base, spec.Name) {
		result.Status = WrongBinary
		result.Details = fmt.Sprintf("resolved executable name %q does not match provider %q", base, spec.Name)
	}
	return result
}

func Evaluate(spec Spec, output string, probeErr error) Result {
	result := baseResult(spec)
	output = safeDetail(output, 512)
	if probeErr != nil {
		result.Status = WrongBinary
		if errors.Is(probeErr, context.DeadlineExceeded) {
			result.Details = "version probe timed out"
		} else if output != "" {
			result.Details = output
		} else {
			result.Details = safeDetail(probeErr.Error(), 256)
		}
		return result
	}
	match := versionPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		result.Status = WrongBinary
		result.Details = "version output did not identify a semantic version"
		if output != "" {
			result.Details += ": " + output
		}
		return result
	}
	result.DetectedVersion = "v" + match[1]
	if !strings.HasPrefix(match[1], spec.CompatiblePrefix) {
		result.Status = Incompatible
		result.Details = "installed provider is outside the tested compatibility family"
		return result
	}
	result.Status = Compatible
	result.Details = "provider identity and version probe succeeded"
	return result
}

func baseResult(spec Spec) Result {
	expected := spec.CompatiblePrefix + "x"
	if spec.PinnedVersion != "" {
		expected += " (worker " + spec.PinnedVersion + ")"
	}
	return Result{Component: spec.DisplayName, Kind: "provider", Required: spec.Required, ExpectedVersion: expected}
}

func safeDetail(value string, limit int) string {
	value = ansiPattern.ReplaceAllString(value, "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
