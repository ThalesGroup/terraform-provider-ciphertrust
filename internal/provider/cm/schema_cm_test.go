package cm

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCMKeyJSON_RevocationFieldsJSONTags guards against a regression of TFIN-286,
// where RevocationReason and RevocationMessage carried swapped JSON tags. It asserts
// the wire format marshals each value under its matching CipherTrust Manager key.
func TestCMKeyJSON_RevocationFieldsJSONTags(t *testing.T) {
	payload := CMKeyJSON{
		RevocationReason:  "REASON_SENTINEL",
		RevocationMessage: "MESSAGE_SENTINEL",
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(CMKeyJSON) failed: %v", err)
	}
	got := string(b)

	mustContain := []string{
		`"revocationReason":"REASON_SENTINEL"`,
		`"revocationMessage":"MESSAGE_SENTINEL"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("marshaled JSON missing %s\ngot: %s", want, got)
		}
	}

	mustNotContain := []string{
		`"revocationReason":"MESSAGE_SENTINEL"`,
		`"revocationMessage":"REASON_SENTINEL"`,
	}
	for _, bad := range mustNotContain {
		if strings.Contains(got, bad) {
			t.Errorf("marshaled JSON has swapped tag %s\ngot: %s", bad, got)
		}
	}
}
