package recon

import "testing"

func TestPipelineDependencyValidation(t *testing.T) {
	for _, bad := range []string{"k", "sh", "sdnka", "sdnhkx", "ss"} {
		if err := Validate(bad); err == nil {
			t.Errorf("pipeline %q should fail", bad)
		}
	}
	if err := Validate("sdnhkga"); err != nil {
		t.Fatal(err)
	}
}
