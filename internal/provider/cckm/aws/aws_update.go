package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// addAliases assigns additional aliases (beyond the first) to an AWS key after creation.
// The first alias is included in the key creation payload.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func addAliases(ctx context.Context, client *common.Client, id string, keyID string, aliases types.Set, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> addAliases]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> addAliases]["+id+"]")
	planAliases := make([]string, 0, len(aliases.Elements()))
	diags.Append(aliases.ElementsAs(ctx, &planAliases, false)...)
	if diags.HasError() {
		return
	}
	response := keyJSON
	for i := 1; i < len(planAliases); i++ {
		alias := planAliases[i]
		payload := AddRemoveAliasPayloadJSON{
			Alias: alias,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating AWS key. Failed to add alias, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
		if err != nil {
			msg := "Error creating AWS key, failed to add alias."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	tflog.Debug(ctx, "[aws_update.go -> addAliases][response:"+redactAWSResponse(response))
}

// updateAliases reconciles the plan's alias list against the key's current aliases, adding and removing
// as needed. Aliases containing "-rotated-" are never removed because they are managed by the rotation job.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func updateAliases(ctx context.Context, id string, client *common.Client, keyID string, aliases types.Set, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> updateAliases]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> updateAliases]["+id+"]")
	var (
		keyAliases []string
		response   string
	)
	for _, a := range gjson.Get(keyJSON, "aws_param.Alias").Array() {
		alias := a.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		keyAliases = append(keyAliases, alias)
	}
	planAliases := make([]string, 0, len(aliases.Elements()))
	if len(aliases.Elements()) != 0 {
		diags.Append(aliases.ElementsAs(ctx, &planAliases, false)...)
		if diags.HasError() {
			return
		}
	}
	for _, planAlias := range planAliases {
		add := true
		for _, keyAlias := range keyAliases {
			if keyAlias == planAlias {
				add = false
				break
			}
		}
		if add {
			payload := AddRemoveAliasPayloadJSON{
				Alias: planAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating AWS key. Failed to add alias, invalid data input."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to add alias."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tflog.Debug(ctx, "[aws_update.go -> updateAliases][response:"+redactAWSResponse(response))
		}
	}

	// Remove aliases not in the plan but in the key
	for _, keyAlias := range keyAliases {
		if strings.Contains(keyAlias, "-rotated-") {
			// Dont delete these aliases
			continue
		}
		remove := true
		for _, planAlias := range planAliases {
			if planAlias == keyAlias {
				remove = false
				break
			}
		}
		if remove {
			payload := AddRemoveAliasPayloadJSON{
				Alias: keyAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating AWS key. Failed to remove alias, invalid data input."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/delete-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to remove alias."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tflog.Debug(ctx, "[aws_update.go -> updateAliases][response:"+redactAWSResponse(response))
		}
	}
}

// updateAwsKeyCommon applies description, key policy, and rotation-job changes that are shared across
// all three AWS key resource types. Used by resourceAWSKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
// planInput and stateInput carry only the fields needed for these operations.
func updateAwsKeyCommon(ctx context.Context, id string, client *common.Client, planInput *AWSKeyUpdateInputTFSDK, stateInput *AWSKeyUpdateInputTFSDK, keyJSON string, diags *diag.Diagnostics) {
	if !planInput.Description.IsUnknown() {
		updateDescription(ctx, id, client, planInput.KeyID, planInput.Description, keyJSON, diags)
		if diags.HasError() {
			return
		}
	}
	if planInput.KeyPolicy != nil || stateInput.KeyPolicy != nil {
		updateKeyPolicy(ctx, id, client, planInput, stateInput, diags)
		if diags.HasError() {
			return
		}
	}
	if planInput.EnableRotation != nil || stateInput.EnableRotation != nil {
		enableDisableKeyRotation(ctx, id, client, planInput, stateInput, diags)
		if diags.HasError() {
			return
		}
	}
}

// enableKey enables a disabled AWS key.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func enableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> enableKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> enableKey]["+id+"]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable")
	if err != nil {
		msg := "Error enabling AWS key"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[aws_update.go -> enableKey] key enabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[aws_update.go -> enableKey][response:"+redactAWSResponse(response))
}

// disableKey disables an enabled AWS key.
// Used by resourceAWSKey (Create, Update), resourceAWSByokKey (Create, Update), resourceAWSXKSKey (Create, Update, linked only), resourceAWSCloudHSMKey (Create, Update, linked only).
func disableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> disableKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> disableKey]["+id+"]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable")
	if err != nil {
		msg := "Error disabling AWS key"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[aws_update.go -> disableKey] key disabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[aws_update.go -> disableKey][response:"+redactAWSResponse(response))
}

// updateDescription updates the description of an AWS key if it has changed from the current value.
func updateDescription(ctx context.Context, id string, client *common.Client, keyID string, description types.String, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> updateDescription]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> updateDescription]["+id+"]")
	var (
		keyDescription  string
		planDescription string
	)
	if gjson.Get(keyJSON, "aws_param.Description").Exists() && gjson.Get(keyJSON, "aws_param.Description").String() != "" {
		keyDescription = gjson.Get(keyJSON, "aws_param.Description").String()
	}
	if !description.IsNull() && !description.IsUnknown() {
		planDescription = description.ValueString()
	}
	if planDescription == keyDescription {
		return
	}
	payload := UpdateKeyDescriptionPayloadJSON{
		Description: description.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS key. Failed to update description, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/update-description", payloadJSON)
	if err != nil {
		msg := "Error updating AWS key, failed to update description."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[aws_update.go -> updateDescription] key description updated successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[aws_update.go -> updateDescription][response:"+redactAWSResponse(response))
}

// enableDisableKeyRotation enables or disables the CipherTrust Manager scheduled rotation job for an AWS key
// based on the difference between plan and state. Used by resourceAWSKey, resourceAWSXKSKey, resourceAWSCloudHSMKey.
// When plan has no enable_rotation block but state does, the rotation job is disabled. When plan and state
// differ, the rotation job is enabled with the new plan parameters.
func enableDisableKeyRotation(ctx context.Context, id string, client *common.Client, planInput *AWSKeyUpdateInputTFSDK, stateInput *AWSKeyUpdateInputTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> enableDisableKeyRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> enableDisableKeyRotation]["+id+"]")
	planHasRotation := planInput.EnableRotation != nil
	stateHasRotation := stateInput.EnableRotation != nil
	if !planHasRotation && stateHasRotation {
		disableKeyRotationJob(ctx, id, client, planInput.KeyID, diags)
		if diags.HasError() {
			return
		}
	}
	if planHasRotation && (stateInput.EnableRotation == nil || !reflect.DeepEqual(*planInput.EnableRotation, *stateInput.EnableRotation)) {
		enableKeyRotationJob(ctx, id, client, planInput.KeyID, planInput.EnableRotation, diags)
		if diags.HasError() {
			return
		}
	}
}

// enableKeyRotationJob registers an AWS key with a CipherTrust Manager scheduled rotation job.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey, resourceAWSCloudHSMKey.
func enableKeyRotationJob(ctx context.Context, id string, client *common.Client, keyID string, rotation *AWSKeyEnableRotationTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> enableKeyRotationJob]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> enableKeyRotationJob]["+id+"]")
	if rotation == nil {
		return
	}
	params := rotation
	payload := AWSEnableKeyRotationJobPayloadJSON{
		JobConfigID:                           params.JobConfigID.ValueString(),
		AutoRotateDisableEncrypt:              params.AutoRotateDisableEncrypt.ValueBool(),
		AutoRotateDisableEncryptOnAllAccounts: params.AutoRotateDisableEncryptOnAllAccounts.ValueBool(),
	}
	if params.AutoRotateKeySource.ValueString() != "" {
		payload.AutoRotateKeySource = params.AutoRotateKeySource.ValueStringPointer()
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Failed to enable key rotation for AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-rotation-job", payloadJSON)
	if err != nil {
		msg := "Failed to enable key rotation for AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[aws_update.go -> enableKeyRotationJob] rotation job enabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[aws_update.go -> enableKeyRotationJob][response:"+redactAWSResponse(response))
}

// disableKeyRotationJob removes an AWS key from its CipherTrust Manager scheduled rotation job.
// Used by resourceAWSKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func disableKeyRotationJob(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_update.go -> disableKeyRotationJob]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_update.go -> disableKeyRotationJob]["+id+"]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-rotation-job")
	if err != nil {
		msg := "Error updating AWS key, failed to disable key rotation job for AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[aws_update.go -> disableKeyRotationJob] rotation job disabled successfully. key_id: %s", keyID))
	tflog.Debug(ctx, "[aws_update.go -> disableKeyRotationJob][response:"+redactAWSResponse(response))
}
