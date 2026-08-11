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
	"github.com/tidwall/gjson"
)

const (
	currentVersionError = "cannot be deleted because it is the current key version"
)

// updateKey applies all mutable changes to an OCI key.
func updateKey(ctx context.Context, id string, client *common.Client, keyID string, plan *models.KeyCommonTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> updateKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> updateKey][" + id + "]")

	if !plan.RestoreFromBackup.IsNull() && plan.RestoreFromBackup.ValueString() != "" {
		restoreKeyFromBackup(ctx, id, client, keyID, diags)
		if diags.HasError() {
			return
		}
	}

	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		client.Log.Error(details)
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

	keyJobConfigID := gjson.Get(response, "labels.job_config_id").String()
	if plan.EnableAutoRotation == nil {
		if keyJobConfigID != "" {
			disableSchedulerRotation(ctx, id, client, keyID, diags)
			if diags.HasError() {
				return
			}
		}
	} else {
		planJobConfigID := plan.EnableAutoRotation.JobConfigID.ValueString()
		planKeySource := plan.EnableAutoRotation.KeySource.ValueString()
		keyKeySource := gjson.Get(response, "labels.auto_rotate_key_source").String()
		if planJobConfigID != keyJobConfigID || planKeySource != keyKeySource {
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> deleteOCIKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> deleteOCIKey][" + id + "]")

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
			client.Log.Warn(details)
			diags.AddWarning(details, "")
		} else {
			msg := "Error refreshing OCI key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			client.Log.Error(details)
		}
		return
	}

	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateScheduledForDeletion || keyState == keyStatePendingDeletion {
		msg := "OCI key is already scheduled for or pending deletion, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}
	payload := models.ScheduleForDeletionJSON{
		Days: days,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error scheduling OCI key for deletion, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err = ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error scheduling OCI key for deletion."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), notFoundError) {
			client.Log.Warn(details)
			diags.AddWarning(details, "")
		} else {
			client.Log.Error(details)
			diags.AddError(details, "")
		}
		return
	}
	client.Log.Debug("[oci_key_common.go -> deleteOCIKey][response:" + redactOCIResponse(response) + "]")
}

// getOciVault fetches an OCI vault by its CipherTrust Manager ID.
func getOciVault(ctx context.Context, id string, client *common.Client, vaultID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> getOciVault][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> getOciVault][" + id + "]")

	response, err := client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			var msg string
			if opLabel == "deleting" {
				msg = "OCI vault was not found. It will be removed from state."
			} else {
				msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "OCI vault")
			}
			details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID})
			if opLabel == "deleting" {
				client.Log.Warn(details)
				diags.AddWarning(details, "")
			} else {
				client.Log.Error(details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " OCI vault, failed to read OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// getOciKey fetches an OCI key by its CipherTrust Manager ID.
// Returns (keyJSON, false) on success.
// If the key is not found (404):
//   - opLabel "deleting": warning added, ("", false) returned - resource removed from state.
//   - any other opLabel + vaultID set: vault checked for context; error added, ("", false) returned.
//   - vaultID empty: generic error added, ("", false) returned.
//
// A non-404 key error is always a hard error; ("", false) is returned.
// Callers that do not know the vault ID at call time (e.g. getOciKeyVersion) should pass "".
func getOciKey(ctx context.Context, id string, client *common.Client, vaultID string, keyID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> getOciKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> getOciKey][" + id + "]")

	response, err := client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			if opLabel == "deleting" {
				msg := "OCI key was not found, it will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
				client.Log.Warn(details)
				diags.AddWarning(details, "")
				return ""
			}
			if vaultID != "" {
				_, vaultErr := client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
				if vaultErr != nil {
					if strings.Contains(vaultErr.Error(), notFoundError) {
						msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "OCI vault")
						details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "key_id": keyID})
						client.Log.Error(details)
						diags.AddError(details, "")
					} else {
						msg := "Error reading OCI vault while " + opLabel + " OCI key."
						details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "key_id": keyID, "error": vaultErr.Error()})
						client.Log.Error(details)
						diags.AddError(details, "")
					}
				} else {
					// Vault is reachable but the key is gone.
					msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "OCI key")
					details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "key_id": keyID})
					client.Log.Error(details)
					diags.AddError(details, "")
				}
				return ""
			}
			msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "OCI key")
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}
		msg := "Error " + opLabel + " OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// setKeyState sets the full Terraform state.
func setKeyState(ctx context.Context, id string, client *common.Client, response string, state *models.KeyTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> setKeyState][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> setKeyState][" + id + "]")

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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> setCommonKeyState][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> setCommonKeyState][" + id + "]")

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
	// Capture the plan/prior-state tag values before overwriting, so we can
	// preserve null-vs-empty semantics (see corrections below).
	oldKeyParams := state.KeyParams
	definedTagsJSON := getDefinedTagsFromJSON(client, gjson.Get(response, "oci_params.defined_tags"), diags)
	if diags.HasError() {
		return
	}
	setDefinedTagsState(ctx, definedTagsJSON, &keyParams.DefinedTags, diags)
	if diags.HasError() {
		return
	}
	freeformTagsJSON := getFreeformTagsFromJSON(client, gjson.Get(response, "oci_params.freeform_tags"), diags)
	if diags.HasError() {
		return
	}
	setFreeformTagsState(ctx, freeformTagsJSON, &keyParams.FreeformTags, diags)
	if diags.HasError() {
		return
	}
	// Correct null-vs-empty mismatches caused by the API returning an absent/empty
	// value when the plan or prior state held an explicit empty value (or null).
	if oldKeyParams != nil {
		// freeform_tags: API returned empty map but plan/prior-state had null -> keep null.
		// This prevents "was null, but now cty.MapValEmpty" inconsistency errors.
		//
		if !keyParams.FreeformTags.IsNull() && len(keyParams.FreeformTags.Elements()) == 0 && oldKeyParams.FreeformTags.IsNull() {
			keyParams.FreeformTags = types.MapNull(types.StringType)
		}
		// defined_tags: API returned null set (empty map -> nil slice) but plan/prior-state
		// had an explicit empty set -> restore empty set.
		// This prevents "was cty.SetValEmpty, but now null" inconsistency errors.
		if keyParams.DefinedTags.IsNull() && !oldKeyParams.DefinedTags.IsNull() {
			emptySet, dg2 := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: models.DefinedTagAttribs}, []models.DefinedTagTFSDK{})
			if !dg2.HasError() {
				keyParams.DefinedTags = emptySet
			}
		}
	}
	state.KeyParams = &keyParams
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	labels := getKeyLabelsFromJSON(client, response, state.ID.ValueString(), diags)
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> setKeyVersionSummaryState][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> setKeyVersionSummaryState][" + id + "]")

	filters := url.Values{}
	response, err := client.ListWithFilters(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions", filters)
	if err != nil {
		msg := "Error reading OCI key versions."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> patchKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> patchKey][" + id + "]")

	response, err := client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		msg := "Error reading OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
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

	if plan.KeyParams != nil && !plan.KeyParams.FreeformTags.IsNull() && !plan.KeyParams.FreeformTags.IsUnknown() {
		planFreeformTags := getFreeformTagsFromPlan(ctx, &plan.KeyParams.FreeformTags, diags)
		if diags.HasError() {
			return
		}

		keyFreeformTags := getFreeformTagsFromJSON(client, gjson.Get(response, "oci_params.freeform_tags"), diags)
		if diags.HasError() {
			return
		}

		if !reflect.DeepEqual(planFreeformTags, keyFreeformTags) {
			payload.FreeformTags = planFreeformTags
			sendRequest = true
		}
	}

	if plan.KeyParams != nil && !plan.KeyParams.DefinedTags.IsNull() && !plan.KeyParams.DefinedTags.IsUnknown() {
		planDefinedTags := getDefinedTagsFromPlan(ctx, &plan.KeyParams.DefinedTags, diags)
		if diags.HasError() {
			return
		}

		keyDefinedTags := getDefinedTagsFromJSON(client, gjson.Get(response, "oci_params.defined_tags"), diags)
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
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		response, err = ociUpdateDataV2WithRetry(ctx, client, keyID, common.URL_OCI+"/keys", payloadJSON)
		if err != nil {
			msg := "Error updating OCI key"
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		client.Log.Debug("[oci_key_common.go -> patchKey][response:" + redactOCIResponse(response) + "]")
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
func getKeyLabelsFromJSON(client *common.Client, response string, keyID string, diags *diag.Diagnostics) map[string]string {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for key labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return nil
		}
	}
	return labels
}

// enableSchedulerRotation enables scheduled auto-rotation for an OCI key.
func enableSchedulerRotation(ctx context.Context, id string, client *common.Client, keyID string, tfsdkParams *models.EnableAutoRotationTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> enableSchedulerRotation][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> enableSchedulerRotation][" + id + "]")

	payload := models.EnableAutoRotationJSON{
		AutoRotateKeySource: tfsdkParams.KeySource.ValueString(),
		JobConfigId:         tfsdkParams.JobConfigID.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto rotation for OCI key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err := ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/enable-auto-rotation", payloadJSON)
	if err != nil {
		msg := "Error enabling auto rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[oci_key_common.go -> enableSchedulerRotation][response:" + redactOCIResponse(response) + "]")
}

// disableSchedulerRotation disables scheduled auto-rotation for an OCI key.
func disableSchedulerRotation(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> disableSchedulerRotation][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> disableSchedulerRotation][" + id + "]")

	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/disable-auto-rotation")
	if err != nil {
		msg := "Error updating OCI key, failed to disable scheduled key rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		client.Log.Error(details)
		return
	}
	client.Log.Debug("[oci_key_common.go -> disableSchedulerRotation][response:" + redactOCIResponse(response) + "]")
}

// enableKey enables an OCI key and waits for the state to settle.
func enableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> enableKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> enableKey][" + id + "]")

	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/enable")
	if err != nil {
		msg := "Error enabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[oci_key_common.go -> enableKey][response:" + redactOCIResponse(response) + "]")
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> disableKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> disableKey][" + id + "]")

	response, err := ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/disable")
	if err != nil {
		msg := "Error disabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[oci_key_common.go -> disableKey][response:" + redactOCIResponse(response) + "]")
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> changeKeyCompartment][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> changeKeyCompartment][" + id + "]")

	payload := models.ChangeCompartmentPayload{
		CompartmentID: compartmentID,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error changing OCI key compartment ID, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "compartment_id": compartmentID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err := ociPostDataV2WithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/change-compartment", payloadJSON)
	if err != nil {
		msg := "Error changing OCI key compartment ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "compartment_id": compartmentID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[oci_key_common.go -> changeKeyCompartment][response:" + redactOCIResponse(response) + "]")
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
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> waitForKeyStateChange][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> waitForKeyStateChange][" + id + "]")

	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		client.Log.Error(details)
		return
	}
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	numRetries := int(client.CCKMConfig.OCIOperationTimeout / ociKeySleepSeconds)
	client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForKeyStateChange] key_id: %s waiting for state to change from '%s', max_retries: %d", keyID, currentState, numRetries))
	for retry := 0; retry < numRetries && keyState == currentState; retry++ {
		time.Sleep(time.Duration(ociKeySleepSeconds) * time.Second)
		if refresh {
			response, err = client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
			if err != nil {
				msg := "Error refreshing OCI key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				diags.AddError(details, "")
				client.Log.Error(details)
				return
			}
		} else {
			response, err = client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
			if err != nil {
				msg := "Error reading OCI key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				client.Log.Error(details)
				diags.AddError(details, "")
				return
			}
		}
		keyState = gjson.Get(response, "oci_params.lifecycle_state").String()
		client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForKeyStateChange] retry %d/%d: key_id: %s state: %s", retry+1, numRetries, keyID, keyState))
	}
	if keyState == currentState {
		msg := fmt.Sprintf("Failed to confirm OCI key state has changed from '%s' in the given time. Consider extending provider configuration option 'oci_operation_timeout'.", currentState)
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		client.Log.Error(fmt.Sprintf("[oci_key_common.go -> waitForKeyStateChange] TIMED OUT after %d retries: key_id: %s last_state: %s", numRetries, keyID, keyState))
		client.Log.Error(details)
		diags.AddError(details, "")
	} else if keyState != keyStateEnabled && keyState != keyStateDisabled {
		client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForKeyStateChange] Resolved: key_id: %s state changed from '%s' to '%s' (warning: not ENABLED/DISABLED)", keyID, currentState, keyState))
		msg := "OCI key is neither enabled or disabled."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
	} else {
		client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForKeyStateChange] Resolved: key_id: %s state changed from '%s' to '%s'.", keyID, currentState, keyState))
	}
	client.Log.Debug("[oci_key_common.go -> waitForKeyStateChange][response:" + redactOCIResponse(response) + "]")
}

// restoreKeyFromBackup restores an OCI key from its most recent backup.
// After the restore POST succeeds it waits until every key version's updatedAt
// field changes in CM, signalling that checkKeyAndAllKeyVersionStatus has run.
// The wait ends when all versions have been updated, or when 30 seconds have
// passed since the last observed change (whichever comes first).
func restoreKeyFromBackup(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> restoreKeyFromBackup][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> restoreKeyFromBackup][" + id + "]")

	// Snapshot pre-restore updatedAt for each version.
	versionsURL := common.URL_OCI + "/keys/" + keyID + "/versions"
	preJSON, err := client.ListWithFilters(ctx, id, versionsURL, url.Values{})
	if err != nil {
		msg := "Error listing OCI key versions before restore."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	preSnapshot := make(map[string]string) // cckm version id -> updatedAt string
	for _, v := range gjson.Get(preJSON, "resources").Array() {
		vid := gjson.Get(v.String(), "id").String()
		uat := gjson.Get(v.String(), "updatedAt").String()
		preSnapshot[vid] = uat
	}
	client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> restoreKeyFromBackup] key_id: %s pre-restore snapshot: %d versions", keyID, len(preSnapshot)))

	// Perform the restore.
	_, err = ociPostNoDataWithRetry(ctx, client, id, common.URL_OCI+"/keys/"+keyID+"/restore")
	if err != nil {
		msg := "Error restoring OCI key from backup."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}

	// If there were no versions to watch, nothing to wait for.
	if len(preSnapshot) == 0 {
		client.Log.Debug("[oci_key_common.go -> restoreKeyFromBackup] no pre-restore versions to watch.")
		return
	}
	waitForOCIKeyVersions(ctx, id, client, keyID, versionsURL, preSnapshot)

	// After the version-change wait, CM's background task may still be writing
	// back to the key record. Poll GET /oci/keys/:id until it returns a clean
	// 200 response before handing control back to the caller (which will call
	// patchKey and then Read, both of which need the key to be queryable).
	waitForOCIKeyReadable(ctx, id, client, keyID, diags)
}

// waitForOCIKeyReadable polls GET /oci/keys/:id until the request succeeds (200)
// or the 60-second deadline is reached. It retries on any error (including HTTP
// 500 returned by CM while the post-restore background task is still running).
func waitForOCIKeyReadable(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> waitForOCIKeyReadable][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> waitForOCIKeyReadable][" + id + "]")

	const (
		readableTimeout  = 60 * time.Second
		readableInterval = 5 * time.Second
	)
	deadline := time.Now().Add(readableTimeout)
	attempt := 0
	for {
		attempt++
		_, err := client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
		if err == nil {
			client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyReadable] key_id: %s readable after %d attempt(s)", keyID, attempt))
			return
		}
		if time.Now().After(deadline) {
			msg := "Timed out waiting for restored OCI key to become readable."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "error": err.Error()})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyReadable] attempt %d key_id: %s not yet readable (%s), retrying in %s",
			attempt, keyID, strings.Split(err.Error(), "\n")[0], readableInterval))
		time.Sleep(readableInterval)
	}
}

// waitForOCIKeyVersions polls the key versions list until every version whose ID appears
// in preSnapshot has a different updatedAt value, signalling that CM has processed the
// restore. The poll ends early if all versions have been updated, or after a 30-second
// idle window (no new changes observed).
func waitForOCIKeyVersions(ctx context.Context, id string, client *common.Client, keyID string, versionsURL string, preSnapshot map[string]string) {
	client.Log.Debug(common.MSG_METHOD_START + "[oci_key_common.go -> waitForOCIKeyVersions][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[oci_key_common.go -> waitForOCIKeyVersions][" + id + "]")

	const idleTimeout = 30 * time.Second
	const pollInterval = 2 * time.Second
	changed := make(map[string]bool, len(preSnapshot))
	lastChangeTime := time.Now()
	loop := 0

	for {
		time.Sleep(pollInterval)

		postJSON, listErr := client.ListWithFilters(ctx, id, versionsURL, url.Values{})
		if listErr != nil {
			client.Log.Warn(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyVersions] loop: %d error listing OCI key versions: %s", loop, listErr.Error()))
		} else {
			for _, v := range gjson.Get(postJSON, "resources").Array() {
				vid := gjson.Get(v.String(), "id").String()
				uat := gjson.Get(v.String(), "updatedAt").String()
				if !changed[vid] && uat != preSnapshot[vid] {
					client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyVersions] loop: %d oldUpdatedAt: %s newUpdatedAt: %s version %s", loop, preSnapshot[vid], uat, vid))
					changed[vid] = true
					lastChangeTime = time.Now()
				}
			}
		}

		if len(changed) == len(preSnapshot) {
			client.Log.Debug(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyVersions] resolved loop: %d all %d key versions updated after restore", loop, len(preSnapshot)))
			break
		}
		if time.Since(lastChangeTime) > idleTimeout {
			client.Log.Warn(fmt.Sprintf("[oci_key_common.go -> waitForOCIKeyVersions] TIMED OUT after %d polls. %d/%d versions updated. key_id: %s", loop, len(changed), len(preSnapshot), keyID))
			break
		}
		loop++
	}
}
