package cckm

import (
	"context"
	"encoding/json"
	"fmt"
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

func deleteKeyVersion(ctx context.Context, id string, client *common.Client, keyID string, versionID string, days int64, diags *diag.Diagnostics) {
	payload := models.ScheduleForDeletionJSON{
		Days: days,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error scheduling OCI key version for deletion, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := client.PostDataV2(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions/"+versionID+"/schedule-deletion", payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), currentVersionError) {
			//msg := "The current version of the can only deleted when the key is deleted."
			//details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "version_id": versionID})
			//diags.AddWarning(details, "")
			return
		}
		msg := "Error scheduling OCI key version for deletion."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			diags.AddError(details, "")
		}
		return
	}
	tflog.Trace(ctx, "[oci_key_version_common.go -> Delete][response:"+response)
}

func setCommonKeyVersionState(ctx context.Context, response string, state *models.KeyVersionTFSDK, diags *diag.Diagnostics) {
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.RefreshedAt = types.StringValue(gjson.Get(response, "refreshed_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	keyVersionParams := models.KeyVersionParamsTFSDK{
		CompartmentID:            types.StringValue(gjson.Get(response, "oci_key_version_params.compartment_id").String()),
		IsPrimary:                types.BoolValue(gjson.Get(response, "oci_key_version_params.is_primary").Bool()),
		KeyID:                    types.StringValue(gjson.Get(response, "oci_key_version_params.key_id").String()),
		LifecycleState:           types.StringValue(gjson.Get(response, "oci_key_version_params.lifecycle_state").String()),
		Origin:                   types.StringValue(gjson.Get(response, "oci_key_version_params.origin").String()),
		PublicKey:                types.StringValue(gjson.Get(response, "oci_key_version_params.public_key").String()),
		ReplicationID:            types.StringValue(gjson.Get(response, "oci_key_version_params.replication_id").String()),
		RestoredFromKeyVersionID: types.StringValue(gjson.Get(response, "oci_key_version_params.restored_from_key_version_id").String()),
		TimeCreated:              types.StringValue(gjson.Get(response, "oci_key_version_params.time_created").String()),
		TimeOfDeletion:           types.StringValue(gjson.Get(response, "oci_key_version_params.time_of_deletion").String()),
		VersionID:                types.StringValue(gjson.Get(response, "oci_key_version_params.version_id").String()),
		VaultID:                  types.StringValue(gjson.Get(response, "vault_id").String()),
	}
	setOciKeyVersionParamsState(ctx, &keyVersionParams, &state.KeyVersionParams, diags)
	if diags.HasError() {
		return
	}
}

func setOciKeyVersionParamsState(ctx context.Context, keyVersionParams *models.KeyVersionParamsTFSDK, state *types.Object, diags *diag.Diagnostics) {
	var keyVersionParamsObjectValue basetypes.ObjectValue
	var dg diag.Diagnostics
	keyVersionParamsObjectValue, dg = types.ObjectValueFrom(ctx, models.KeyVersionParamsTFSDKAttribs, keyVersionParams)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state, dg = keyVersionParamsObjectValue.ToObjectValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}

func setHYOKKeyVersionParams(ctx context.Context, hyokKeyVersionParams *models.DataSourceHYOKKeyVersionParamsTFSDK, state *types.Object, diags *diag.Diagnostics) {
	var dg diag.Diagnostics
	var hyokVersionParamsObjectValue basetypes.ObjectValue
	hyokVersionParamsObjectValue, dg = types.ObjectValueFrom(ctx, models.HYOKKeyVersionParamsTFSDKAttribs, hyokKeyVersionParams)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state, dg = hyokVersionParamsObjectValue.ToObjectValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}

func waitForKeyVersionState(ctx context.Context, id string, client *common.Client, keyID string, versionID string, expectedState string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[oci_key_version_common.go -> waitForKeyVersionState]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[oci_key_version_common.go -> waitForKeyVersionState]["+id+"]")
	response, err := client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	keyVersionState := gjson.Get(response, "oci_key_version_params.lifecycle_state").String()
	numRetries := int(client.CCKMConfig.OCIOperationTimeout / ociKeySleepSeconds)
	tStart := time.Now()
	for retry := 0; retry < numRetries && keyVersionState != expectedState; retry++ {
		if time.Since(tStart).Seconds() > refreshTokenSeconds {
			if err = client.RefreshToken(ctx, id); err != nil {
				msg := "Error refreshing authentication token."
				details := utils.ApiError(msg, map[string]interface{}{
					"error":  err.Error(),
					"key_id": keyID,
				})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
		}
		time.Sleep(time.Duration(ociKeySleepSeconds) * time.Second)
		response, err = client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
		if err != nil {
			msg := "Error reading OCI key version."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		keyVersionState = gjson.Get(response, "oci_key_version_params.lifecycle_state").String()
	}
	if keyVersionState != expectedState {
		msg := fmt.Sprintf("Failed to confirm OCI key version state is '%s' in the given time. Consider extending provider configuration option 'oci_operation_timeout'.", expectedState)
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
	}
	tflog.Trace(ctx, "[oci_key_version_common.go -> waitForKeyVersionState][response:"+response)
}
