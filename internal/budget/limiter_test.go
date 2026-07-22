package budget

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestHostBudgetBlocksSameHostAndAllowsDifferentHost(t *testing.T) {
	limiter := NewLocal(Limits{Program: 3, Provider: 3, Host: 1})
	release, err := limiter.Acquire(context.Background(), Request{ProgramID: "program", Provider: "httpx", Hosts: []string{"a.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := limiter.Acquire(blockedCtx, Request{ProgramID: "program", Provider: "katana", Hosts: []string{"a.example.test"}}); err == nil {
		t.Fatal("same-host request bypassed host budget")
	}

	differentRelease, err := limiter.Acquire(context.Background(), Request{ProgramID: "program", Provider: "katana", Hosts: []string{"b.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	differentRelease()
}

func TestProviderBudgetReleasesExactlyOnce(t *testing.T) {
	limiter := NewLocal(Limits{Program: 4, Provider: 1, Host: 4})
	release, err := limiter.Acquire(context.Background(), Request{ProgramID: "one", Provider: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()
	second, err := limiter.Acquire(context.Background(), Request{ProgramID: "two", Provider: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	second()
}

func TestHostsFromInputNormalizesTargetFields(t *testing.T) {
	raw := json.RawMessage(`{"targets":["https://A.Example.test/path","a.example.test:443","https://[2001:db8::1]/"],"domains":["B.example.test."],"reason":"ignore.example.test"}`)
	want := []string{"2001:db8::1", "a.example.test", "b.example.test"}
	if got := HostsFromInput(raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %#v, want %#v", got, want)
	}
}
