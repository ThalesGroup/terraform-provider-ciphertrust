package cm

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCMKeyJSON_RevocationTagSerialization pins the wire contract for the
// revocation fields on ciphertrust_cm_key (TFIN-286). It guards against the
// historical bug where RevocationReason and RevocationMessage were serialized
// with swapped JSON tags, storing each value in the wrong CM field.
func TestCMKeyJSON_RevocationTagSerialization(t *testing.T) {
	payload := CMKeyJSON{
		RevocationReason:  "Unspecified",
		RevocationMessage: "decommissioned",
	}

	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal CMKeyJSON: %s", err)
	}
	got := string(out)

	if !strings.Contains(got, `"revocationReason":"Unspecified"`) {
		t.Errorf("expected revocationReason to serialize to %q, got: %s", "Unspecified", got)
	}
	if !strings.Contains(got, `"revocationMessage":"decommissioned"`) {
		t.Errorf("expected revocationMessage to serialize to %q, got: %s", "decommissioned", got)
	}

	// Explicitly assert the tags are not swapped.
	if strings.Contains(got, `"revocationReason":"decommissioned"`) {
		t.Errorf("revocationReason carries the message value — tags are swapped: %s", got)
	}
	if strings.Contains(got, `"revocationMessage":"Unspecified"`) {
		t.Errorf("revocationMessage carries the reason value — tags are swapped: %s", got)
	}
}

// TestCMKeyJSON_RevocationTagOmitempty guards against accidental loss of the
// omitempty option during the tag edit and covers the Optional-only-one-set
// edge case: each revocation field must be absent from the wire payload when
// it is empty.
func TestCMKeyJSON_RevocationTagOmitempty(t *testing.T) {
	t.Run("only reason set", func(t *testing.T) {
		out, err := json.Marshal(CMKeyJSON{RevocationReason: "Unspecified"})
		if err != nil {
			t.Fatalf("failed to marshal CMKeyJSON: %s", err)
		}
		got := string(out)
		if !strings.Contains(got, `"revocationReason":"Unspecified"`) {
			t.Errorf("expected revocationReason present, got: %s", got)
		}
		if strings.Contains(got, "revocationMessage") {
			t.Errorf("expected revocationMessage omitted when empty, got: %s", got)
		}
	})

	t.Run("only message set", func(t *testing.T) {
		out, err := json.Marshal(CMKeyJSON{RevocationMessage: "decommissioned"})
		if err != nil {
			t.Fatalf("failed to marshal CMKeyJSON: %s", err)
		}
		got := string(out)
		if !strings.Contains(got, `"revocationMessage":"decommissioned"`) {
			t.Errorf("expected revocationMessage present, got: %s", got)
		}
		if strings.Contains(got, "revocationReason") {
			t.Errorf("expected revocationReason omitted when empty, got: %s", got)
		}
	})
}
