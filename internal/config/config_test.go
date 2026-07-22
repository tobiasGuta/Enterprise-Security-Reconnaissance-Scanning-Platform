package config

import (
	"strings"
	"testing"
)

func TestLoadAndSecretSafeString(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://user:secret@localhost/db", "REDIS_ADDR": "localhost:6379", "REDIS_PASSWORD": "redis-secret", "NUCLEI_RATE_LIMIT": "17", "HTTPX_EXECUTABLE": `C:\tools\projectdiscovery\httpx.exe`}
	c, err := LoadWith(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Nuclei.RateLimit != 17 {
		t.Fatalf("rate limit=%d", c.Nuclei.RateLimit)
	}
	if c.Tools.HTTPX != `C:\tools\projectdiscovery\httpx.exe` || c.Tools.DNSx != "dnsx" {
		t.Fatalf("unexpected tool executables: %#v", c.Tools)
	}
	safe := c.String()
	if strings.Contains(safe, "secret") {
		t.Fatalf("config string leaked a secret: %s", safe)
	}
}
func TestConfigValidation(t *testing.T) {
	tests := []map[string]string{{}, {"DATABASE_URL": "x", "REDIS_ADDR": "missing-port"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "RECON_HEADLESS": "maybe"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "NUCLEI_RATE_LIMIT": "0"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "RECON_PIPELINE": "sx"}}
	for i, env := range tests {
		if _, err := LoadWith(func(k string) string { return env[k] }); err == nil {
			t.Errorf("case %d expected error", i)
		}
	}
}
