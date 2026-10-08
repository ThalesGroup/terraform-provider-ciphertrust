package cckm

import (
	"context"
	"encoding/json"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

// azureKeyEnableBackup enables the scheduled backup job for a key.
func azureKeyEnableBackup(ctx context.Context, id string, client *common.Client, keyID string, backup *models.EnableAutoBackupTFSDK, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_key_backup_scheduler.go -> azureKeyEnableBackup][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_key_backup_scheduler.go -> azureKeyEnableBackup][" + id + "]")

	payload := models.AzureEnableBackupPayloadJSON{
		BackupJobConfigID: backup.JobConfigID.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto backup for Azure key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/enable-backup-job", payloadJSON)
	if err != nil {
		msg := "Error enabling auto backup for Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[azure_key_backup_scheduler.go -> azureKeyEnableBackup][response:" + response + "]")
}

// azureKeyDisableBackup disables the scheduled backup job for a key.
func azureKeyDisableBackup(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_key_backup_scheduler.go -> azureKeyDisableBackup][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_key_backup_scheduler.go -> azureKeyDisableBackup][" + id + "]")

	response, err := azurePostNoDataWithRetry(ctx, id, client, azureKeysEndpoint+"/"+keyID+"/disable-backup-job")
	if err != nil {
		msg := "Error disabling auto backup for Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Debug("[azure_key_backup_scheduler.go -> azureKeyDisableBackup][response:" + response + "]")
}

// azureKeyApplyBackup compares enable_auto_backup in the plan with backup_config of the key and enables or
// disables the backup job when they differ. It returns true if a backup call was made.
func azureKeyApplyBackup(ctx context.Context, id string, client *common.Client, keyID string, plan *models.AzureKeyTFSDK, response string, diags *diag.Diagnostics) bool {
	keyJobConfigID := gjson.Get(response, "backup_config.backup_job_config_id").String()
	if plan.EnableAutoBackup == nil {
		if keyJobConfigID == "" {
			return false
		}
		azureKeyDisableBackup(ctx, id, client, keyID, diags)
		return true
	}
	if plan.EnableAutoBackup.JobConfigID.ValueString() == keyJobConfigID {
		return false
	}
	azureKeyEnableBackup(ctx, id, client, keyID, plan.EnableAutoBackup, diags)
	return true
}

// azureKeyBackupFromConfig builds enable_auto_backup from backup_config of the key. It returns nil if the
// key has no backup job.
func azureKeyBackupFromConfig(response string) *models.EnableAutoBackupTFSDK {
	jobConfigID := gjson.Get(response, "backup_config.backup_job_config_id").String()
	if jobConfigID == "" {
		return nil
	}
	return &models.EnableAutoBackupTFSDK{
		JobConfigID: types.StringValue(jobConfigID),
	}
}

// azureKeyBackupConfigMap builds the backup_config map from the response. No backup_config is an empty map.
func azureKeyBackupConfigMap(ctx context.Context, response string, diags *diag.Diagnostics) types.Map {
	backupConfig := make(map[string]string)
	for k, v := range gjson.Get(response, "backup_config").Map() {
		backupConfig[k] = v.String()
	}
	backupConfigMap, d := types.MapValueFrom(ctx, types.StringType, backupConfig)
	diags.Append(d...)
	return backupConfigMap
}
