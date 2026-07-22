package normalize

import "testing"

func TestURLNormalization(t *testing.T) {
	got, err := URL("HTTPS://Example.COM:443/a/../b?z=2&a=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/b?a=1&z=2" {
		t.Fatalf("got %s", got)
	}
}
func TestRouteDedupOnlyDynamicSegments(t *testing.T) {
	legitimate := []string{"users", "admin", "billing", "payments"}
	for _, p := range legitimate {
		k, err := Endpoint("https://example.com/api/"+p, "GET", "application/json")
		if err != nil {
			t.Fatal(err)
		}
		if k.RouteSignature != "/api/"+p {
			t.Fatalf("legitimate path collapsed: %s", k.RouteSignature)
		}
	}
	dynamic := []string{"123", "550e8400-e29b-41d4-a716-446655440000", "507f1f77bcf86cd799439011", "2026-07-21", "aB9_x7K2pQ4-rT8z"}
	for _, p := range dynamic {
		k, _ := Endpoint("https://example.com/items/"+p, "GET", "")
		if k.RouteSignature != "/items/{id}" {
			t.Errorf("%q was not generalized: %s", p, k.RouteSignature)
		}
	}
}
func TestEndpointIdentityPreservesMethodContentTypeAndParameterNames(t *testing.T) {
	a, _ := Endpoint("https://example.com/api?id=1&q=x", "GET", "application/json; charset=utf-8")
	b, _ := Endpoint("https://example.com/api?id=2&q=y", "GET", "application/json")
	if a.Digest != b.Digest {
		t.Fatal("query values should normalize")
	}
	c, _ := Endpoint("https://example.com/api?id=2&q=y", "POST", "application/json")
	if a.Digest == c.Digest {
		t.Fatal("method must affect identity")
	}
	d, _ := Endpoint("https://example.com/api?id=2", "GET", "application/json")
	if a.Digest == d.Digest {
		t.Fatal("parameter schema must affect identity")
	}
}
