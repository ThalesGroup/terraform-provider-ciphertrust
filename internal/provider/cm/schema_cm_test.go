package cm

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCMKeyJSON_RevocationFieldSerialization guards against a regression of
// TFIN-194, where the json struct tags for RevocationReason and
// RevocationMessage on CMKeyJSON were transposed, causing Create/Update to
// persist each value under the opposite CM API field.
func TestCMKeyJSON_RevocationFieldSerialization(t *testing.T) {
	payload := CMKeyJSON{
		RevocationReason:  "UNSPECIFIED",
		RevocationMessage: "decommissioned",
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal CMKeyJSON: %v", err)
	}
	got := string(b)

	if !strings.Contains(got, `"revocationReason":"UNSPECIFIED"`) {
		t.Errorf("expected revocationReason to carry the reason value; got %s", got)
	}
	if !strings.Contains(got, `"revocationMessage":"decommissioned"`) {
		t.Errorf("expected revocationMessage to carry the message value; got %s", got)
	}

	// The bug serialized the values under the swapped keys; ensure that is gone.
	if strings.Contains(got, `"revocationReason":"decommissioned"`) {
		t.Errorf("revocationReason must not carry the message value; got %s", got)
	}
	if strings.Contains(got, `"revocationMessage":"UNSPECIFIED"`) {
		t.Errorf("revocationMessage must not carry the reason value; got %s", got)
	}
}
