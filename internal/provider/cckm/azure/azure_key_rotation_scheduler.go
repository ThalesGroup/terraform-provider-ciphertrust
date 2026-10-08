package cckm

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

// azureKeyEnableRotation enables the scheduled rotation job for a key.
func azureKeyEnableRotation(ctx context.Context, id string, client *common.Client, keyID string, rot *models.EnableAutoRotationTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_key_rotation_scheduler.go -> azureKeyEnableRotation][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_key_rotation_scheduler.go -> azureKeyEnableRotation][" + id + "]")

	payload := models.AzureEnableRotationPayloadJSON{
		JobConfigID:         rot.JobConfigID.ValueString(),
		AutoRotateKeySource: rot.KeySource.ValueString(),
		AutoRotateKeyType:   rot.KeyType.ValueString(),
		AutoRotateKeySize:   rot.KeySize.ValueInt64(),
		AutoRotateECName:    rot.ECName.ValueString(),
		AutoRotateEnableKey: rot.EnableKey.ValueBool(),
	}
	if !rot.ReleasePolicy.IsNull() && !rot.ReleasePolicy.IsUnknown() {
		payload.AutoRotateReleasePolicy = json.RawMessage(rot.ReleasePolicy.ValueString())
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto rotation for Azure key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/enable-rotation-job", payloadJSON)
	if err != nil {
		msg := "Error enabling auto rotation for Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[azure_key_rotation_scheduler.go -> azureKeyEnableRotation][response:" + response + "]")
}

// azureKeyDisableRotation disables the scheduled rotation job for a key.
func azureKeyDisableRotation(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_key_rotation_scheduler.go -> azureKeyDisableRotation][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_key_rotation_scheduler.go -> azureKeyDisableRotation][" + id + "]")

	response, err := azurePostNoDataWithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/disable-rotation-job")
	if err != nil {
		msg := "Error disabling auto rotation for Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[azure_key_rotation_scheduler.go -> azureKeyDisableRotation][response:" + response + "]")
}

// azureKeyApplyRotation compares enable_auto_rotation in the plan with the labels of the key and enables or
// disables the rotation job when they differ. It returns true if a rotation call was made.
func azureKeyApplyRotation(ctx context.Context, id string, client *common.Client, keyID string, plan *models.AzureKeyTFSDK, response string, diags *diag.Diagnostics) bool {
	keyJobConfigID := gjson.Get(response, "labels.job_config_id").String()
	if plan.EnableAutoRotation == nil {
		if keyJobConfigID == "" {
			return false
		}
		azureKeyDisableRotation(ctx, id, client, keyID, diags)
		return true
	}
	if !azureKeyRotationDiffers(plan.EnableAutoRotation, response) {
		return false
	}
	azureKeyEnableRotation(ctx, id, client, keyID, plan.EnableAutoRotation, diags)
	return true
}

// azureKeyRotationDiffers returns true if a value in the plan differs from the rotation labels of the key.
// An optional value that is not configured is ignored.
func azureKeyRotationDiffers(rot *models.EnableAutoRotationTFSDK, response string) bool {
	labels := gjson.Get(response, "labels")
	if rot.JobConfigID.ValueString() != labels.Get("job_config_id").String() ||
		rot.KeySource.ValueString() != labels.Get("auto_rotate_key_source").String() ||
		rot.KeyType.ValueString() != labels.Get("auto_rotate_key_type").String() {
		return true
	}
	if !rot.KeySize.IsNull() && rot.KeySize.ValueInt64() != labels.Get("auto_rotate_key_size").Int() {
		return true
	}
	if !rot.ECName.IsNull() && rot.ECName.ValueString() != labels.Get("auto_rotate_ec_name").String() {
		return true
	}
	enableKey := labels.Get("auto_rotate_enable_key")
	if !rot.EnableKey.IsNull() && !rot.EnableKey.IsUnknown() && (!enableKey.Exists() || rot.EnableKey.ValueBool() != enableKey.Bool()) {
		return true
	}
	if !rot.ReleasePolicy.IsNull() && !rot.ReleasePolicy.IsUnknown() {
		var want, got interface{}
		policy := labels.Get("auto_rotate_release_policy")
		if json.Unmarshal([]byte(rot.ReleasePolicy.ValueString()), &want) != nil ||
			!policy.Exists() || json.Unmarshal([]byte(policy.Raw), &got) != nil ||
			!reflect.DeepEqual(want, got) {
			return true
		}
	}
	return false
}

// azureKeyRotationFromLabels builds enable_auto_rotation from the labels of the key. It returns nil if the
// key has no rotation job. Values that are not in the labels are null.
func azureKeyRotationFromLabels(response string) *models.EnableAutoRotationTFSDK {
	labels := gjson.Get(response, "labels")
	jobConfigID := labels.Get("job_config_id").String()
	if jobConfigID == "" {
		return nil
	}
	rot := &models.EnableAutoRotationTFSDK{
		JobConfigID:   types.StringValue(jobConfigID),
		KeySource:     azureKeyOptString(labels.Get("auto_rotate_key_source").String()),
		KeyType:       azureKeyOptString(labels.Get("auto_rotate_key_type").String()),
		KeySize:       azureKeyOptInt64(labels.Get("auto_rotate_key_size").Int()),
		ECName:        azureKeyOptString(labels.Get("auto_rotate_ec_name").String()),
		EnableKey:     types.BoolNull(),
		ReleasePolicy: types.StringNull(),
	}
	if enableKey := labels.Get("auto_rotate_enable_key"); enableKey.Exists() {
		rot.EnableKey = types.BoolValue(enableKey.Bool())
	}
	if policy := labels.Get("auto_rotate_release_policy"); policy.Exists() && policy.Type != gjson.Null {
		rot.ReleasePolicy = types.StringValue(policy.Raw)
	}
	return rot
}
