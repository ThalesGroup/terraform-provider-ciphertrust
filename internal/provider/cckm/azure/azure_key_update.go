package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/tidwall/gjson"
)

// azureKeyUpdate updates the tags, key_ops, enabled, activation_date and expiration_date of a key
// and its rotation and backup jobs. The key is read first and the plan is compared with the key, not
// with state. Only values that differ are sent. If nothing differs no request is made. A 409 on the
// update is retried. On success plan holds the state to store.
func azureKeyUpdate(ctx context.Context, id string, client *common.Client, plan *models.AzureKeyTFSDK, state *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_key_update.go -> azureKeyUpdate][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_key_update.go -> azureKeyUpdate][" + id + "]")

	keyID := state.ID.ValueString()

	response := getAzureKey(ctx, id, client, keyID, "updating", diags)
	if diags.HasError() || response == "" {
		return
	}
	if gjson.Get(response, "deleted").Bool() || gjson.Get(response, "key_soft_deleted_in_azure").Bool() {
		msg := fmt.Sprintf(utils.PendingDeletionReadFmt, "Azure", "key", "deleted", "Azure")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}

	// Attributes that are not configured are unknown in the plan only when they are not in state.
	plan.ID = state.ID
	if plan.VaultName.IsUnknown() {
		plan.VaultName = state.VaultName
	}

	// Update the rotation and backup jobs before the other attributes.
	rotationChanged := azureKeyApplyRotation(ctx, id, client, keyID, plan, response, diags)
	if diags.HasError() {
		return
	}
	backupChanged := azureKeyApplyBackup(ctx, id, client, keyID, plan, response, diags)
	if diags.HasError() {
		return
	}
	if rotationChanged || backupChanged {
		getResp, getErr := client.GetById(ctx, id, keyID, azureKeysEndpoint)
		if getErr != nil {
			msg := "Error reading Azure key after changing auto rotation or auto backup."
			details := utils.ApiError(msg, map[string]interface{}{"error": getErr.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		response = getResp
	}

	updatePayload := azureKeyBuildUpdatePayload(id, client, plan, response, diags)
	if diags.HasError() {
		return
	}
	if updatePayload == nil {
		client.Log.Info("[azure_key_update.go -> azureKeyUpdate][" + id + "] Nothing to update for key " + keyID)
	} else {
		payloadJSON, err := json.Marshal(updatePayload)
		if err != nil {
			msg := "Error updating Azure key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		patchResp, err := azureUpdateDataV2WithRetry(ctx, id, client, azureKeysEndpoint, keyID, payloadJSON)
		if err != nil {
			msg := "Error updating Azure key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		response = patchResp

		// The update has been applied. A failure to refresh is a warning so the new values are stored in state.
		getResp, getErr := client.GetById(ctx, id, keyID, azureKeysEndpoint)
		if getErr != nil {
			msg := "Error reading Azure key after update. State is set from the update response."
			details := utils.ApiError(msg, map[string]interface{}{"error": getErr.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddWarning(details, "")
		} else {
			response = getResp
		}
	}
	client.Log.Debug("[azure_key_update.go -> azureKeyUpdate][response:" + response + "]")

	azureKeySetState(ctx, response, plan, diags)
}
