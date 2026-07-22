package command

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOSRunnerTransportsStdinWithoutShell(t *testing.T) {
	runner := OSRunner{}
	stdout, stderr, exit, err := runner.Run(context.Background(), os.Args[0], helperArgs("echo"), []byte("one.example\ntwo.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != "one.example\ntwo.example\n" || len(stderr) != 0 || exit != 0 {
		t.Fatalf("stdout=%q stderr=%q exit=%d", stdout, stderr, exit)
	}
	stdout, _, exit, err = runner.Run(context.Background(), os.Args[0], helperArgs("echo"), nil)
	if err != nil || len(stdout) != 0 || exit != 0 {
		t.Fatalf("empty stdin failed: stdout=%q exit=%d err=%v", stdout, exit, err)
	}
}

func TestOSRunnerPreservesFailureStderrAndExitCode(t *testing.T) {
	_, stderr, exit, err := (OSRunner{}).Run(context.Background(), os.Args[0], helperArgs("fail"), nil)
	if err == nil || exit != 7 || !strings.Contains(string(stderr), "resolver configuration failed") {
		t.Fatalf("stderr=%q exit=%d err=%v", stderr, exit, err)
	}
}

func TestOSRunnerContextCancellationTerminatesChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, _, err := (OSRunner{}).Run(ctx, os.Args[0], helperArgs("wait"), nil)
	if err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("child was not cancelled promptly: %v", err)
	}
}

func helperArgs(mode string) []string {
	return []string{"-test.run=^TestCommandHelperProcess$", "--", "command-helper", mode}
}

func TestCommandHelperProcess(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "command-helper" {
			index = i
			break
		}
	}
	if index < 0 || index+1 >= len(os.Args) {
		return
	}
	switch os.Args[index+1] {
	case "echo":
		data, _ := io.ReadAll(os.Stdin)
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "fail":
		_, _ = os.Stderr.WriteString("resolver configuration failed\n")
		os.Exit(7)
	case "wait":
		time.Sleep(30 * time.Second)
	}
}
