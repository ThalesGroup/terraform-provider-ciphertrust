package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// getParamsFromResponse – cckm_key_rotation_params hydration
// ---------------------------------------------------------------------------

// Test_CM_GetParamsFromResponse_CCKMKeyRotation_HydratedFromResponse verifies
// cckm_key_rotation_params is populated by Read even when plan.Operation
// starts empty (e.g. partial import state).
func Test_CM_GetParamsFromResponse_CCKMKeyRotation_HydratedFromResponse(t *testing.T) {
	response := `{
		"id":        "sched-1",
		"uri":       "scheduler/sched-1",
		"operation": "cckm_key_rotation",
		"run_at":    "0 1 * * *",
		"job_config_params": {
			"cloud_name": "aws",
			"aws_param": {
				"retain_alias":    true,
				"rotate_material": false
			},
			"expiration":     "7d",
			"expire_in":      "30d",
			"rotation_after": "90d"
		}
	}`

	// plan.Operation is deliberately left as the zero value (empty / null),
	// mimicking the state that exists immediately after a terraform import
	// before the framework re-populates the attribute.
	plan := &CreateJobConfigParamsTFSDK{}
	plan.Operation = types.StringNull()

	var diags diag.Diagnostics
	getParamsFromResponse(context.Background(), response, plan, &diags, hclog.NewNullLogger())

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	// operation must be updated from the response
	if plan.Operation.ValueString() != "cckm_key_rotation" {
		t.Errorf("plan.Operation: want cckm_key_rotation, got %q", plan.Operation.ValueString())
	}

	// params block must be hydrated
	if plan.CCKMKeyRotationParams == nil {
		t.Fatal("CCKMKeyRotationParams is nil; want non-nil")
	}
	p := plan.CCKMKeyRotationParams
	if p.CloudName.ValueString() != "aws" {
		t.Errorf("CloudName: want aws, got %q", p.CloudName.ValueString())
	}
	if !p.RetainAlias.ValueBool() {
		t.Error("RetainAlias: want true, got false")
	}
	if p.RotateMaterial.ValueBool() {
		t.Error("RotateMaterial: want false, got true")
	}
	if p.Expiration.ValueString() != "7d" {
		t.Errorf("Expiration: want 7d, got %q", p.Expiration.ValueString())
	}
	if p.ExpireIn.ValueString() != "30d" {
		t.Errorf("ExpireIn: want 30d, got %q", p.ExpireIn.ValueString())
	}
	if p.RotationAfter.ValueString() != "90d" {
		t.Errorf("RotationAfter: want 90d, got %q", p.RotationAfter.ValueString())
	}
}

// Test_CM_GetParamsFromResponse_CCKMKeyRotation_OperationAlreadyInState confirms
// that the fix is backward-compatible: when plan.Operation is already set
// (the normal steady-state Read path) the params are still hydrated correctly.
func Test_CM_GetParamsFromResponse_CCKMKeyRotation_OperationAlreadyInState(t *testing.T) {
	response := `{
		"id":        "sched-2",
		"operation": "cckm_key_rotation",
		"job_config_params": {
			"cloud_name": "oci",
			"aws_param": {
				"retain_alias":    false,
				"rotate_material": true
			}
		}
	}`

	plan := &CreateJobConfigParamsTFSDK{}
	plan.Operation = types.StringValue("cckm_key_rotation") // pre-populated from state

	var diags diag.Diagnostics
	getParamsFromResponse(context.Background(), response, plan, &diags, hclog.NewNullLogger())

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if plan.CCKMKeyRotationParams == nil {
		t.Fatal("CCKMKeyRotationParams is nil; want non-nil")
	}
	if plan.CCKMKeyRotationParams.CloudName.ValueString() != "oci" {
		t.Errorf("CloudName: want oci, got %q", plan.CCKMKeyRotationParams.CloudName.ValueString())
	}
	if !plan.CCKMKeyRotationParams.RotateMaterial.ValueBool() {
		t.Error("RotateMaterial: want true, got false")
	}
}

// Test_CM_GetParamsFromResponse_DatabaseBackup verifies that the database_backup
// case is unaffected by the operation-derivation change.
func Test_CM_GetParamsFromResponse_DatabaseBackup(t *testing.T) {
	response := `{
		"id":        "sched-3",
		"operation": "database_backup",
		"job_config_params": {
			"scope":          "system",
			"retentionCount": 5,
			"tiedToHSM":      true,
			"do_scp":         false
		}
	}`

	plan := &CreateJobConfigParamsTFSDK{}
	plan.Operation = types.StringNull() // empty, fixed by reading from response

	var diags diag.Diagnostics
	getParamsFromResponse(context.Background(), response, plan, &diags, hclog.NewNullLogger())

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if plan.Operation.ValueString() != "database_backup" {
		t.Errorf("Operation: want database_backup, got %q", plan.Operation.ValueString())
	}
	if plan.DatabaseBackupParams == nil {
		t.Fatal("DatabaseBackupParams is nil; want non-nil")
	}
	if plan.DatabaseBackupParams.Scope.ValueString() != "system" {
		t.Errorf("Scope: want system, got %q", plan.DatabaseBackupParams.Scope.ValueString())
	}
	if plan.DatabaseBackupParams.RetentionCount.ValueInt64() != 5 {
		t.Errorf("RetentionCount: want 5, got %d", plan.DatabaseBackupParams.RetentionCount.ValueInt64())
	}
	if !plan.DatabaseBackupParams.TiedToHSM.ValueBool() {
		t.Error("TiedToHSM: want true, got false")
	}
}

// Test_CM_GetParamsFromResponse_CCKMXKSCredentialRotation ensures the
// cckm_xks_credential_rotation case hydrates correctly.
func Test_CM_GetParamsFromResponse_CCKMXKSCredentialRotation(t *testing.T) {
	response := `{
		"id":        "sched-4",
		"operation": "cckm_xks_credential_rotation",
		"job_config_params": {
			"cloud_name": "aws"
		}
	}`

	plan := &CreateJobConfigParamsTFSDK{}
	plan.Operation = types.StringNull()

	var diags diag.Diagnostics
	getParamsFromResponse(context.Background(), response, plan, &diags, hclog.NewNullLogger())

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if plan.CCKMXksRotateCredentialsParams == nil {
		t.Fatal("CCKMXksRotateCredentialsParams is nil; want non-nil")
	}
	if plan.CCKMXksRotateCredentialsParams.CloudName.ValueString() != "aws" {
		t.Errorf("CloudName: want aws, got %q", plan.CCKMXksRotateCredentialsParams.CloudName.ValueString())
	}
}

// Test_CM_GetParamsFromResponse_NoOperationInResponse confirms that when the API
// response omits the "operation" field (unusual but defensive), the existing
// plan.Operation value is retained as-is and no panic occurs.
func Test_CM_GetParamsFromResponse_NoOperationInResponse(t *testing.T) {
	response := `{"id": "sched-5"}`

	plan := &CreateJobConfigParamsTFSDK{}
	plan.Operation = types.StringValue("cckm_key_rotation")

	var diags diag.Diagnostics
	getParamsFromResponse(context.Background(), response, plan, &diags, hclog.NewNullLogger())

	// operation should remain as whatever was in plan (fallback)
	if plan.Operation.ValueString() != "cckm_key_rotation" {
		t.Errorf("Operation: want cckm_key_rotation (fallback), got %q", plan.Operation.ValueString())
	}
	// CCKMKeyRotationParams is non-nil: the switch still matched via the fallback
	// plan.Operation value, so the struct is allocated — fields will just be empty
	// strings / false since job_config_params is absent from the response.
	if plan.CCKMKeyRotationParams == nil {
		t.Fatal("CCKMKeyRotationParams is nil; want non-nil (switch matched via fallback operation)")
	}
}
