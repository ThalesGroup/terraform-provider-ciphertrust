package cm

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Test_CM_Unit_Policy_UpdateIsNoOpWarning verifies that Update() never calls the API and
// only sets a warning diagnostic, since ciphertrust_policies has no PATCH endpoint on CM.
func Test_CM_Unit_Policy_UpdateIsNoOpWarning(t *testing.T) {
	r := resourceCMPolicy{client: &common.Client{Log: hclog.NewNullLogger()}}
	var resp resource.UpdateResponse
	r.Update(context.Background(), resource.UpdateRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no error diagnostics, got: %v", resp.Diagnostics.Errors())
	}
	if resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("expected exactly one warning diagnostic, got %d", resp.Diagnostics.WarningsCount())
	}
	if got := resp.Diagnostics.Warnings()[0].Summary(); got != "Cannot update a CM policy." {
		t.Errorf("expected summary %q, got %q", "Cannot update a CM policy.", got)
	}
}

// Test_CM_Unit_PolicyAttachment_UpdateIsNoOpWarning verifies that Update() never calls the
// API and only sets a warning diagnostic, since ciphertrust_policy_attachments has no PATCH
// endpoint on CM.
func Test_CM_Unit_PolicyAttachment_UpdateIsNoOpWarning(t *testing.T) {
	r := resourceCMPolicyAttachment{client: &common.Client{Log: hclog.NewNullLogger()}}
	var resp resource.UpdateResponse
	r.Update(context.Background(), resource.UpdateRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no error diagnostics, got: %v", resp.Diagnostics.Errors())
	}
	if resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("expected exactly one warning diagnostic, got %d", resp.Diagnostics.WarningsCount())
	}
	if got := resp.Diagnostics.Warnings()[0].Summary(); got != "Cannot update a CM policy attachment." {
		t.Errorf("expected summary %q, got %q", "Cannot update a CM policy attachment.", got)
	}
}
