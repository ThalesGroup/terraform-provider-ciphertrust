package cm

import (
	"encoding/json"
	"testing"
)

// TestCMKeyJSONRevocationTags guards against a regression of TFIN-286, where the
// JSON struct tags for RevocationReason and RevocationMessage on CMKeyJSON were
// swapped, causing each value to be persisted under the wrong field on
// CipherTrust Manager and resulting in perpetual drift.
func TestCMKeyJSONRevocationTags(t *testing.T) {
	payload := CMKeyJSON{
		RevocationReason:  "reason-sentinel",
		RevocationMessage: "message-sentinel",
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal CMKeyJSON: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal CMKeyJSON: %v", err)
	}

	if got := decoded["revocationReason"]; got != "reason-sentinel" {
		t.Errorf("revocationReason serialized incorrectly: got %v, want %q", got, "reason-sentinel")
	}
	if got := decoded["revocationMessage"]; got != "message-sentinel" {
		t.Errorf("revocationMessage serialized incorrectly: got %v, want %q", got, "message-sentinel")
	}
}
