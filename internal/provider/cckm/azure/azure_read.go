package cckm

import (
	"context"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// getAzureKey fetches an Azure key by its CipherTrust Manager ID.
// It is used by the Azure key resource.
// On 404:
//   - opLabel "deleting": warning added (Terraform removes from state), "" returned.
//   - any other opLabel: error added, "" returned.
//
// Any non-404 error adds a hard error diagnostic and returns "".
func getAzureKey(ctx context.Context, id string, client *common.Client, keyID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_read.go -> getAzureKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_read.go -> getAzureKey][" + id + "]")

	response, err := client.GetById(ctx, id, keyID, azureKeysEndpoint)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			if opLabel == "deleting" {
				msg := "Azure key was not found. It will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
				client.Log.Warn(details)
				diags.AddWarning(details, "")
				return ""
			}
			msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure key")
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}
		msg := "Error " + opLabel + " Azure key, failed to read Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}
