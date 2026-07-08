package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// TestUnit_TrialLicense_UpdateReturnsError verifies that Update() always returns an error
// diagnostic, regardless of input, since ciphertrust_trial_license does not support updates.
func TestUnit_TrialLicense_UpdateReturnsError(t *testing.T) {
	r := resourceCMTrialLicense{}
	var resp resource.UpdateResponse
	r.Update(context.Background(), resource.UpdateRequest{}, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected Update() to set a diagnostic error, but none was set")
	}
	if got := resp.Diagnostics.Errors()[0].Summary(); got != "Update Not Supported" {
		t.Errorf("expected summary %q, got %q", "Update Not Supported", got)
	}
}
