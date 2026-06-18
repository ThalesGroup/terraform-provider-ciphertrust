package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

const (
	currentVersionError = "cannot be deleted because it is the current key version"
)

// updateKey applies all mutable changes to an OCI key.
func updateKey(ctx context.Context, id string, client *common.Client, keyID string, plan *models.KeyCommonTFSDK, state *models.KeyCommonTFSDK, diags *diag.Diagnostics) {
	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}

	keyEnabled := gjson.Get(response, "oci_params.lifecycle_state").String() == keyStateEnabled
	keyDisabled := gjson.Get(response, "oci_params.lifecycle_state").String() == keyStateDisabled
	planEnableKey := false
	if !plan.EnableKey.IsUnknown() {
		planEnableKey = plan.EnableKey.ValueBool()
		if planEnableKey && keyDisabled {
			enableKey(ctx, id, client, keyID, diags)
			if diags.HasError() {
				return
			}
		}
	}

	keyRotationEnabled := gjson.Get(response, "auto_rotate").Bool()
	if plan.EnableAutoRotation == nil {
		if keyRotationEnabled {
			disableSchedulerRotation(ctx, id, client, keyID, diags)
			if diags.HasError() {
				return
			}
		}
	} else {
		if !keyRotationEnabled || plan.EnableAutoRotation != state.EnableAutoRotation {
			enableSchedulerRotation(ctx, id, client, keyID, plan.EnableAutoRotation, diags)
			if diags.HasError() {
				return
			}
		}
	}

	patchKey(ctx, id, client, keyID, plan, diags)
	if diags.HasError() {
		return
	}

	if plan.KeyParams != nil && !plan.KeyParams.CompartmentID.IsUnknown() {
		planCompartmentID := plan.KeyParams.CompartmentID.ValueString()
		keyCompartmentID := gjson.Get(response, "oci_params.compartment_id").String()
		if planCompartmentID != keyCompartmentID {
			changeKeyCompartment(ctx, id, client, keyID, planCompartmentID, diags)
			if diags.HasError() {
				return
			}
		}
	}

	if !plan.EnableKey.IsUnknown() {
		if !planEnableKey && keyEnabled {
			disableKey(ctx, id, client, keyID, diags)
			if diags.HasError() {
				return
			}
		}
	}
}

// deleteOCIKey schedules an OCI key for deletion.
func deleteOCIKey(ctx context.Context, id string, client *common.Client, vaultID string, keyID string, days int64, diags *diag.Diagnostics) {
	keyJSON := getOciKey(ctx, id, client, vaultID, keyID, "deleting", diags)
	if diags.HasError() {
		return // key error - resource kept in state
	}
	if keyJSON == "" {
		return // key not found (404) - warning already added, Terraform removes from state
	}

	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "OCI key was not found, it will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			msg := "Error refreshing OCI key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			tflog.Error(ctx, details)
		}
		return
	}

	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateScheduledForDeletion {
		msg := "OCI key is already scheduled for deletion, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
		return
	} else {
		payload := models.ScheduleForDeletionJSON{
			Days: days,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error scheduling OCI key for deletion, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err = ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/schedule-deletion", payloadJSON)
		if err != nil {
			msg := "Error scheduling OCI key for deletion."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			if strings.Contains(err.Error(), notFoundError) {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return
		}
	}
	tflog.Debug(ctx, "[oci_key_common.go -> deleteOCIKey][response:"+redactOCIResponse(response)+"]")
}

// getOciVault fetches an OCI vault by its CipherTrust Manager ID.
func getOciVault(ctx context.Context, id string, client *common.Client, vaultID string, opLabel string, diags *diag.Diagnostics) string {
	response, err := client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "OCI vault (" + vaultID + ") was not found."
			details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID})
			if opLabel == "deleting" {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " OCI vault, failed to read OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// getOciKey fetches an OCI key by its CipherTrust Manager ID.
// If vaultID is non-empty the vault is verified to exist first (opLabel "reading");
// a missing vault is always a hard error. Callers that do not know the vault ID
// at call time (e.g. getOciKeyVersion) should pass "".
func getOciKey(ctx context.Context, id string, client *common.Client, vaultID string, keyID string, opLabel string, diags *diag.Diagnostics) string {
	if vaultID != "" {
		getOciVault(ctx, id, client, vaultID, "reading", diags)
		if diags.HasError() {
			return ""
		}
	}
	response, err := client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "OCI key (" + keyID + ") was not found."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			if opLabel == "deleting" {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// setKeyState sets the full Terraform state. Used by resourceCCKMOCIKey and resourceCCKMOCIByokKey.
func setKeyState(ctx context.Context, id string, client *common.Client, response string, state *models.KeyTFSDK, diags *diag.Diagnostics) {
	setCommonKeyState(ctx, id, client, response, &state.KeyCommonTFSDK, diags)
	if diags.HasError() {
		return
	}
	state.VaultID = types.StringValue(gjson.Get(response, "vault_id").String())
	if state.KeyParams.LifecycleState.ValueString() == "ENABLED" {
		state.EnableKey = types.BoolValue(true)
	} else {
		state.EnableKey = types.BoolValue(false)
	}
	state.Vault = types.StringValue(gjson.Get(response, "cckm_vault_id").String())
}

// setCommonKeyState populates all shared TFSDK state fields from a raw CM API response string.
// Makes a secondary API call to GET /oci/keys/:id/versions to populate version_summary.
func setCommonKeyState(ctx context.Context, id string, client *common.Client, response string, state *models.KeyCommonTFSDK, diags *diag.Diagnostics) {
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.AutoRotate = types.BoolValue(gjson.Get(response, "auto_rotate").Bool())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CompartmentName = types.StringValue(gjson.Get(response, "compartment_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	keyParams := models.KeyParamsTFSDK{
		Algorithm:         types.StringValue(gjson.Get(response, "oci_params.algorithm").String()),
		CompartmentID:     types.StringValue(gjson.Get(response, "oci_params.compartment_id").String()),
		CurrentKeyVersion: types.StringValue(gjson.Get(response, "oci_params.current_key_version").String()),
		DisplayName:       types.StringValue(gjson.Get(response, "oci_params.display_name").String()),
		IsPrimary:         types.BoolValue(gjson.Get(response, "oci_params.is_primary").Bool()),
		KeyID:             types.StringValue(gjson.Get(response, "oci_params.key_id").String()),
		Length:            types.Int64Value(gjson.Get(response, "oci_params.length").Int()),
		LifecycleState:    types.StringValue(gjson.Get(response, "oci_params.lifecycle_state").String()),
		ProtectionMode:    types.StringValue(gjson.Get(response, "oci_params.protection_mode").String()),
		ReplicationID:     types.StringValue(gjson.Get(response, "oci_params.replication_id").String()),
		RestoredFromKeyID: types.StringValue(gjson.Get(response, "oci_params.restored_from_key_id").String()),
		TimeCreated:       types.StringValue(gjson.Get(response, "oci_params.time_created").String()),
		TimeOfDeletion:    types.StringValue(gjson.Get(response, "oci_params.time_of_deletion").String()),
		VaultName:         types.StringValue(gjson.Get(response, "oci_params.vault_name").String()),
	}
	keyParams.CurveID = types.StringValue(gjson.Get(response, "oci_params.curve_id").String())
	definedTagsJSON := getDefinedTagsFromJSON(ctx, gjson.Get(response, "oci_params.defined_tags"), diags)
	if diags.HasError() {
		return
	}
	setDefinedTagsState(ctx, definedTagsJSON, &keyParams.DefinedTags, diags)
	if diags.HasError() {
		return
	}
	freeformTagsJSON := getFreeformTagsFromJSON(ctx, gjson.Get(response, "oci_params.freeform_tags"), diags)
	if diags.HasError() {
		return
	}
	setFreeformTagsState(ctx, freeformTagsJSON, &keyParams.FreeformTags, diags)
	if diags.HasError() {
		return
	}
	state.KeyParams = &keyParams
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	labels := getKeyLabelsFromJSON(ctx, response, state.ID.ValueString(), diags)
	if diags.HasError() {
		return
	}
	var dg diag.Diagnostics
	state.Labels, dg = types.MapValueFrom(ctx, types.StringType, labels)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	state.Name = types.StringValue(gjson.Get(response, "oci_params.display_name").String())
	state.RefreshedAt = types.StringValue(gjson.Get(response, "refreshed_at").String())
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.Tenancy = types.StringValue(gjson.Get(response, "tenancy").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	setKeyVersionSummaryState(ctx, id, client, gjson.Get(response, "id").String(), &state.KeyVersionSummary, diags)
	if diags.HasError() {
		return
	}
	if state.EnableAutoRotation == nil && len(labels) != 0 {
		state.EnableAutoRotation = new(models.EnableAutoRotationTFSDK)
		if v, ok := labels["job_config_id"]; ok {
			state.EnableAutoRotation.JobConfigID = types.StringValue(v)
		}
		if v, ok := labels["auto_rotate_key_source"]; ok {
			state.EnableAutoRotation.KeySource = types.StringValue(v)
		}
	}
}

// setKeyVersionSummaryState fetches the key version list and populates the version_summary state.
func setKeyVersionSummaryState(ctx context.Context, id string, client *common.Client, keyID string, state *types.List, diags *diag.Diagnostics) {
	filters := url.Values{}
	response, err := client.ListWithFilters(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions", filters)
	if err != nil {
		msg := "Error reading OCI key versions."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	var versions []models.KeyVersionSummaryTFSDK
	for _, v := range gjson.Get(response, "resources").Array() {
		version := models.KeyVersionSummaryTFSDK{
			CCKMVersionID: types.StringValue(gjson.Get(v.String(), "id").String()),
			CreatedAt:     types.StringValue(gjson.Get(v.String(), "createdAt").String()),
			SourceKeyID:   types.StringValue(gjson.Get(v.String(), "source_key_identifier").String()),
			SourceKeyName: types.StringValue(gjson.Get(v.String(), "source_key_name").String()),
			SourceKeyTier: types.StringValue(gjson.Get(v.String(), "source_key_tier").String()),
			VersionID:     types.StringValue(gjson.Get(v.String(), "oci_key_version_params.version_id").String()),
		}
		versions = append(versions, version)
	}
	var versionListValue basetypes.ListValue
	var dg diag.Diagnostics
	versionListValue, dg = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: models.KeyVersionSummaryAttribs}, versions)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	stateList, dg := versionListValue.ToListValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state = stateList
}

// patchKey sends a PATCH request to update display_name, freeform_tags, or defined_tags on an OCI key.
func patchKey(ctx context.Context, id string, client *common.Client, keyID string, plan *models.KeyCommonTFSDK, diags *diag.Diagnostics) {
	response, err := client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		msg := "Error reading OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	var payload models.PatchKeyCommonPayload
	sendRequest := false

	if !plan.Name.IsUnknown() {
		planDisplayName := plan.Name.ValueString()
		keyDisplayName := gjson.Get(response, "oci_params.display_name").String()
		if planDisplayName != keyDisplayName {
			payload.DisplayName = &planDisplayName
			sendRequest = true
		}
	}

	if plan.KeyParams != nil && !plan.KeyParams.FreeformTags.IsUnknown() {
		planFreeformTags := getFreeformTagsFromPlan(ctx, &plan.KeyParams.FreeformTags, diags)
		if diags.HasError() {
			return
		}

		keyFreeformTags := getFreeformTagsFromJSON(ctx, gjson.Get(response, "oci_params.freeform_tags"), diags)
		if diags.HasError() {
			return
		}

		if !reflect.DeepEqual(planFreeformTags, keyFreeformTags) {
			payload.FreeformTags = planFreeformTags
			sendRequest = true
		}
	}

	if plan.KeyParams != nil && !plan.KeyParams.DefinedTags.IsUnknown() {
		planDefinedTags := getDefinedTagsFromPlan(ctx, &plan.KeyParams.DefinedTags, diags)
		if diags.HasError() {
			return
		}

		keyDefinedTags := getDefinedTagsFromJSON(ctx, gjson.Get(response, "oci_params.defined_tags"), diags)
		if diags.HasError() {
			return
		}

		if !reflect.DeepEqual(planDefinedTags, keyDefinedTags) {
			payload.DefinedTags = planDefinedTags
			sendRequest = true
		}
	}

	if sendRequest {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error updating OCI key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err = ociUpdateDataV2WithRetry(ctx, client, keyID, common.URL_OCI+"/keys", payloadJSON)
		if err != nil {
			msg := "Error updating OCI key"
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Debug(ctx, "[oci_key_common.go -> updateKey][response:"+redactOCIResponse(response)+"]")
		keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
		if keyState == keyStateUpdating {
			waitForKeyStateChange(ctx, id, client, keyID, keyState, true, diags)
			if diags.HasError() {
				return
			}
		}
	}
}

// getKeyLabelsFromJSON parses the CM-side labels map from a raw API response string.
func getKeyLabelsFromJSON(ctx context.Context, response string, keyID string, diags *diag.Diagnostics) map[string]string {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for key labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return nil
		}
	}
	return labels
}

// enableSchedulerRotation enables scheduled auto-rotation for an OCI key.
func enableSchedulerRotation(ctx context.Context, id string, client *common.Client, keyID string, tfsdkParams *models.EnableAutoRotationTFSDK, diags *diag.Diagnostics) {
	payload := models.EnableAutoRotationJSON{
		AutoRotateKeySource: tfsdkParams.KeySource.ValueString(),
		JobConfigId:         tfsdkParams.JobConfigID.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto rotation for OCI key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/enable-auto-rotation", payloadJSON)
	if err != nil {
		msg := "Error enabling auto rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[oci_key_common.go -> enableSchedulerRotation][response:"+redactOCIResponse(response)+"]")
}

// disableSchedulerRotation disables scheduled auto-rotation for an OCI key.
func disableSchedulerRotation(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/disable-auto-rotation")
	if err != nil {
		msg := "Error updating OCI key, failed to disable scheduled key rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	tflog.Debug(ctx, "[oci_key_common.go -> disableSchedulerRotation][response:"+redactOCIResponse(response)+"]")
}

// enableKey enables an OCI key and waits for the state to settle.
func enableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/enable")
	if err != nil {
		msg := "Error enabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[oci_key_common.go -> enableKey][response:"+redactOCIResponse(response)+"]")
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateEnabling {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, false, diags)
		if diags.HasError() {
			return
		}
	}
}

// disableKey disables an OCI key and waits for the state to settle.
func disableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/disable")
	if err != nil {
		msg := "Error disabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[oci_key_common.go -> disableKey][response:"+redactOCIResponse(response)+"]")
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateDisabling {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, false, diags)
		if diags.HasError() {
			return
		}
	}
}

// changeKeyCompartment moves an OCI key to a different compartment.
func changeKeyCompartment(ctx context.Context, id string, client *common.Client, keyID string, compartmentID string, diags *diag.Diagnostics) {
	payload := models.ChangeCompartmentPayload{
		CompartmentID: compartmentID,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error changing OCI key compartment ID, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "compartment_id": compartmentID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/change-compartment", payloadJSON)
	if err != nil {
		msg := "Error changing OCI key compartment ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "compartment_id": compartmentID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[oci_key_common.go -> changeKeyCompartment][response:"+redactOCIResponse(response)+"]")
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateUpdating || keyState == keyStateChangingCompartment {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, true, diags)
		if diags.HasError() {
			return
		}
	}
}

// waitForKeyStateChange polls until the OCI key's lifecycle_state differs from currentState.
// If refresh is true, polls via the /refresh endpoint; otherwise polls via GET.
// Returns an error if the state does not change within the configured oci_operation_timeout.
// Returns a warning if the final state is neither ENABLED nor DISABLED.
func waitForKeyStateChange(ctx context.Context, id string, client *common.Client, keyID string, currentState string, refresh bool, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	numRetries := int(client.CCKMConfig.OCIOperationTimeout / ociKeySleepSeconds)
	tStart := time.Now()
	for retry := 0; retry < numRetries && keyState == currentState; retry++ {
		time.Sleep(time.Duration(ociKeySleepSeconds) * time.Second)
		if time.Since(tStart).Seconds() > refreshTokenSeconds {
			if err = client.RefreshToken(ctx, id); err != nil {
				msg := "Error refreshing CipherTrust Manager authentication token."
				details := utils.ApiError(msg, map[string]interface{}{
					"error":  err.Error(),
					"key_id": keyID,
				})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tStart = time.Now()
		}
		if refresh {
			response, err = client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
			if err != nil {
				msg := "Error refreshing OCI key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				diags.AddError(details, "")
				tflog.Error(ctx, details)
				return
			}
		} else {
			response, err = client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
			if err != nil {
				msg := "Error reading OCI key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
		}
		keyState = gjson.Get(response, "oci_params.lifecycle_state").String()
	}
	if keyState == currentState {
		msg := fmt.Sprintf("Failed to confirm OCI key state has changed from '%s' in the given time. Consider extending provider configuration option 'oci_operation_timeout'.", currentState)
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
	} else if keyState != keyStateEnabled && keyState != keyStateDisabled {
		msg := "OCI key is neither enabled or disabled."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
	}
	tflog.Debug(ctx, "[oci_key_common.go -> waitForKeyStateChange][response:"+redactOCIResponse(response)+"]")
}
