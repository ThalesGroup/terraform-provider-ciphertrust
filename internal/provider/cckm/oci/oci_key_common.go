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

func updateKey(ctx context.Context, id string, client *common.Client, keyID string, plan *models.KeyCommonTFSDK, state *models.KeyCommonTFSDK, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
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

	keyRotationEnabled := gjson.Get(response, "labels").Exists()
	if plan.EnableAutoRotation != nil {
		planRotationEnabled := plan.EnableAutoRotation != nil
		if keyRotationEnabled && !planRotationEnabled {
			disableSchedulerRotation(ctx, id, client, keyID, diags)
			if diags.HasError() {
				return
			}
		}
		if planRotationEnabled && (!keyRotationEnabled || plan.EnableAutoRotation != state.EnableAutoRotation) {
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

func deleteKey(ctx context.Context, id string, client *common.Client, keyID string, days int64, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			diags.AddError(details, "")
			tflog.Error(ctx, details)
		}
		return
	}

	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateScheduledForDeletion {
		msg := "The OCI key is already pending deletion."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
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
		response, err = client.PostDataV2(ctx, id, common.URL_OCI+"/keys/"+keyID+"/schedule-deletion", payloadJSON)
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
	tflog.Trace(ctx, "[oci_key_common.go -> deleteKey][response:"+response)
}

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
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}

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
		response, err = client.UpdateDataV2(ctx, keyID, common.URL_OCI+"/keys", payloadJSON)
		if err != nil {
			msg := "Error updating OCI key"
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Trace(ctx, "[oci_key_common.go -> updateKey][response:"+response)
		keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
		if keyState == keyStateUpdating {
			waitForKeyStateChange(ctx, id, client, keyID, keyState, true, diags)
			if diags.HasError() {
				return
			}
		}
	}
}

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
	response, err := client.PostDataV2(ctx, id, common.URL_OCI+"/keys/"+keyID+"/enable-auto-rotation", payloadJSON)
	if err != nil {
		msg := "Error enabling auto rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[oci_key_common.go -> enableSchedulerRotation][response:"+response)
}

func disableSchedulerRotation(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/disable-auto-rotation")
	if err != nil {
		msg := "Error updating OCI key, failed to disable scheduled key rotation for OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	tflog.Trace(ctx, "[oci_key_common.go -> disableSchedulerRotation][response:"+response)
}

func enableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/enable")
	if err != nil {
		msg := "Error enabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[oci_key_common.go -> enableKey][response:"+response)
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateEnabling {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, false, diags)
		if diags.HasError() {
			return
		}
	}
}

func disableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	response, err := client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/disable")
	if err != nil {
		msg := "Error disabling OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[oci_key_common.go -> disableKey][response:"+response)
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateDisabling {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, false, diags)
		if diags.HasError() {
			return
		}
	}
}

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
	response, err := client.PostDataV2(ctx, id, common.URL_OCI+"/keys/"+keyID+"/change-compartment", payloadJSON)
	if err != nil {
		msg := "Error changing OCI key compartment ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "compartment_id": compartmentID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[oci_key_common.go -> changeKeyCompartment][response:"+response)
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if keyState == keyStateUpdating || keyState == keyStateChangingCompartment {
		waitForKeyStateChange(ctx, id, client, keyID, keyState, true, diags)
		if diags.HasError() {
			return
		}
	}
}

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
	tflog.Trace(ctx, "[oci_key_common.go -> waitForKeyStateChange][response:"+response)
}
