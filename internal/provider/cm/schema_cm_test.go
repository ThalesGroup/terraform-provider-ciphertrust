package cm

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCMKeyJSON_RevocationTagsMarshaling locks the serialization contract for the
// revocation fields on CMKeyJSON. Regression guard for TFIN-286, where the
// json struct tags for RevocationReason and RevocationMessage were swapped,
// causing the values to be persisted under the wrong keys on CipherTrust Manager.
func TestCMKeyJSON_RevocationTagsMarshaling(t *testing.T) {
	t.Run("values marshal under matching keys", func(t *testing.T) {
		payload := CMKeyJSON{
			RevocationReason:  "REASON_SENTINEL",
			RevocationMessage: "MESSAGE_SENTINEL",
		}

		out, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal returned an unexpected error: %v", err)
		}

		got := string(out)

		if !strings.Contains(got, `"revocationReason":"REASON_SENTINEL"`) {
			t.Errorf("expected marshaled JSON to contain %q, got: %s", `"revocationReason":"REASON_SENTINEL"`, got)
		}
		if !strings.Contains(got, `"revocationMessage":"MESSAGE_SENTINEL"`) {
			t.Errorf("expected marshaled JSON to contain %q, got: %s", `"revocationMessage":"MESSAGE_SENTINEL"`, got)
		}
	})

	t.Run("omitempty preserved when both fields empty", func(t *testing.T) {
		payload := CMKeyJSON{}

		out, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal returned an unexpected error: %v", err)
		}

		got := string(out)

		if strings.Contains(got, "revocationReason") {
			t.Errorf("expected marshaled JSON to omit revocationReason, got: %s", got)
		}
		if strings.Contains(got, "revocationMessage") {
			t.Errorf("expected marshaled JSON to omit revocationMessage, got: %s", got)
		}
	})
}

// TestCMKeyJSON_RevocationFieldsUnmarshal asserts the symmetric case: the
// revocationReason/revocationMessage JSON keys deserialize into the matching
// Go fields.
func TestCMKeyJSON_RevocationFieldsUnmarshal(t *testing.T) {
	input := `{"revocationReason":"compromise","revocationMessage":"key exposed in logs"}`

	var payload CMKeyJSON
	if err := json.Unmarshal([]byte(input), &payload); err != nil {
		t.Fatalf("json.Unmarshal returned an unexpected error: %v", err)
	}

	if payload.RevocationReason != "compromise" {
		t.Errorf("RevocationReason = %q, want %q", payload.RevocationReason, "compromise")
	}
	if payload.RevocationMessage != "key exposed in logs" {
		t.Errorf("RevocationMessage = %q, want %q", payload.RevocationMessage, "key exposed in logs")
	}
}
