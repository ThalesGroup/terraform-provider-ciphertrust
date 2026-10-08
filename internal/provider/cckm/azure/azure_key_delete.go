package cckm

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/tidwall/gjson"
)

// azureKeyPurgeable is the text in the recovery level of keys in a vault that allows purging.
const azureKeyPurgeable = "Purgeable"

// azureKeyLatestVersion lists the latest version of a key. It returns the list response and
// the ID of the latest version, which is "" when the key is not found.
func azureKeyLatestVersion(ctx context.Context, id string, client *common.Client, vaultID string, keyName string) (string, string, error) {
	filters := url.Values{}
	filters.Set("key_name", keyName)
	filters.Set("key_vault_id", vaultID)
	filters.Set("version", "-1")
	listJSON, err := client.ListWithFilters(ctx, id, azureKeysEndpoint, filters)
	if err != nil {
		return "", "", err
	}
	return listJSON, gjson.Get(listJSON, "resources.0.id").String(), nil
}

// azureKeyDelete deletes an Azure key. It is used by the Azure key resource.
//   - The caller fetches the key and passes its response. A 404 is handled by the caller.
//   - If the key is not the latest version of the key name, nothing is done in Azure and the
//     resource is removed from state.
//   - Delete is repeatable. Each call does only what is left to do, using the provider settings
//     at the time of the call, so a destroy operation that failed part way can be run again.
//   - If the key is not soft-deleted or purged it is soft-deleted. Failure is an error.
//   - If the key is not purged, is purgeable and purge_keys_on_delete is true, it is purged.
//     A purge straight after a soft-delete is expected to return 409 until Azure has finished,
//     so the purge is retried. Failure is an error.
//   - If the key is purged (now or by an earlier call) and retain_key_backups_after_purge is
//     false, the key backups are deleted. This makes no Azure call, it only removes the key
//     and its versions from the CCKM database, so it is not retried on 409. Failing to delete
//     backups is a warning.
func azureKeyDelete(ctx context.Context, id string, client *common.Client, keyID string, response string, diags *diag.Diagnostics) {
	vaultID := gjson.Get(response, "key_vault_id").String()
	keyName := gjson.Get(response, "key_name").String()

	mutexKey := fmt.Sprintf("azure-key-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	if vaultID != "" && keyName != "" {
		_, latestID, err := azureKeyLatestVersion(ctx, id, client, vaultID, keyName)
		if err != nil {
			msg := "Error deleting Azure key, failed to list the latest version of the key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "name": keyName})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		if latestID != keyID {
			client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Key " + keyID + " is not the latest version of " + keyName + ", not deleting in Azure")
			return
		}
	}

	settings := client.CCKMConfig.AzureCCKMSettings
	purged := gjson.Get(response, "deleted").Bool()
	softDeleted := gjson.Get(response, "key_soft_deleted_in_azure").Bool()

	if !purged && !softDeleted {
		_, err := azurePostNoDataWithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/soft-delete")
		if err != nil {
			msg := "Error soft deleting Azure key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
		client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Soft deleted Azure key " + keyName)
	}

	if !purged {
		purgeable := strings.Contains(gjson.Get(response, "azure_param.attributes.recoveryLevel").String(), azureKeyPurgeable)
		if !purgeable {
			client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Not purging " + keyName + " as the key is not purgeable")
		} else if !settings.PurgeKeysOnDelete {
			client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Not purging " + keyName + " as purge_keys_on_delete is false")
		} else {
			purgeResp, err := azurePostNoDataWithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/hard-delete")
			if err != nil {
				msg := "Error purging Azure key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				client.Log.Error(details)
				diags.AddError(details, "")
				return
			}
			client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Purged Azure key " + keyName)
			purged = gjson.Get(purgeResp, "deleted").Bool()
		}
	}

	if !purged {
		client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Not deleting backups of " + keyName + " as the key is not purged")
		return
	}

	if settings.RetainKeyBackupsAfterPurge {
		client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Not deleting backups of " + keyName + " as retain_key_backups_after_purge is true")
		return
	}

	// Backups are deleted only when this key is still the latest version and it is purged.
	listJSON, latestID, err := azureKeyLatestVersion(ctx, id, client, vaultID, keyName)
	if err != nil || latestID != keyID || !gjson.Get(listJSON, "resources.0.deleted").Bool() {
		return
	}
	if _, err = client.PostNoData(ctx, id, azureKeysEndpoint+"/"+keyID+"/delete-backup"); err != nil {
		msg := "Failed to delete the key backups of " + keyName + "."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddWarning(details, "")
		return
	}
	client.Log.Info("[azure_key_delete.go -> azureKeyDelete][" + id + "] Deleted backups of Azure key " + keyName)
}
