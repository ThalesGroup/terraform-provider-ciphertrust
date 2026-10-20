package cckm

import (
	"encoding/json"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// azureSecretSetState copies a secret response into state.
func azureSecretSetState(response string, state *AzureSecretTFSDK) error {
	var secret models.AzureSecretJSON
	if err := json.Unmarshal([]byte(response), &secret); err != nil {
		return err
	}
	state.ID = types.StringValue(secret.ID)
	state.Name = azureCertificateKeepIfEmpty(secret.SecretName, state.Name)
	state.VaultID = azureCertificateKeepIfEmpty(secret.KeyVaultID, state.VaultID)

	state.URI = azureCertificateStringOrNull(secret.URI)
	state.Account = azureCertificateStringOrNull(secret.Account)
	state.CreatedAt = azureCertificateStringOrNull(secret.CreatedAt)
	state.UpdatedAt = azureCertificateStringOrNull(secret.UpdatedAt)
	state.SyncedAt = azureCertificateStringOrNull(secret.SyncedAt)
	state.CreatedBy = azureCertificateStringOrNull(secret.CreatedBy)
	state.ModifiedBy = azureCertificateStringOrNull(secret.ModifiedBy)
	state.Status = azureCertificateStringOrNull(secret.Status)
	state.Version = azureCertificateStringOrNull(secret.Version)
	state.VersionCount = types.Int64Value(secret.VersionCount)
	state.Deleted = types.BoolValue(secret.Deleted)
	state.Gone = types.BoolValue(secret.Gone)
	state.SecretSoftDeletedInAzure = types.BoolValue(secret.SecretSoftDeletedInAzure)
	state.BackupAt = azureCertificateStringOrNull(secret.BackupAt)
	state.Backup = types.StringNull()
	if secret.Backup != nil {
		state.Backup = azureCertificateStringOrNull(*secret.Backup)
	}

	state.CloudName = azureCertificateStringOrNull(secret.CloudName)
	state.Region = azureCertificateStringOrNull(secret.Region)
	state.Tenant = azureCertificateStringOrNull(secret.Tenant)
	state.VaultName = azureCertificateStringOrNull(secret.KeyVault)
	state.SoftDeleteEnabled = types.BoolValue(secret.SoftDeleteEnabled)
	state.AzureCreatedAt = azureCertificateStringOrNull(secret.AzureCreatedAt)
	state.AzureUpdatedAt = azureCertificateStringOrNull(secret.AzureUpdatedAt)

	azureSecretSetParams(secret.AzureParam, state)
	return nil
}

// azureSecretSetParams builds azure_params from the response.
func azureSecretSetParams(param models.AzureSecretParamResponseJSON, state *AzureSecretTFSDK) {
	value := attrString(objectAttrs(state.AzureParams), "value")
	if value.IsUnknown() {
		value = types.StringNull()
	}
	state.AzureParams = types.ObjectValueMust(azureSecretParamsAttrTypes, map[string]attr.Value{
		"value":            value,
		"content_type":     azureCertificateStringOrNull(param.ContentType),
		"tags":             azureSecretTags(param.Tags, state.AzureParams),
		"attributes":       azureSecretAttributesObject(param, state.AzureParams),
		"secret_id":        azureCertificateStringOrNull(param.SecretID),
		"recoverable_days": azureCertificateInt64OrNull(param.Attributes.RecoverableDays),
		"recovery_level":   azureCertificateStringOrNull(param.Attributes.RecoveryLevel),
	})
}

// azureSecretTags returns the tags from the response.
func azureSecretTags(tags map[string]string, current types.Object) types.Map {
	if len(tags) == 0 {
		currentTags, ok := objectAttrs(current)["tags"].(types.Map)
		if ok && !currentTags.IsNull() && !currentTags.IsUnknown() && len(currentTags.Elements()) == 0 {
			return currentTags
		}
	}
	return azureCertificateMapOrNull(tags)
}

// azureSecretAttributesObject returns the attributes that can be configured.
func azureSecretAttributesObject(param models.AzureSecretParamResponseJSON, current types.Object) types.Object {
	attrs := param.Attributes
	// The API omits enabled when it is false, so a missing value means false.
	enabled := types.BoolValue(false)
	if attrs.Enabled != nil {
		enabled = types.BoolValue(*attrs.Enabled)
	}
	currentAttrs := objectAttrs(objectAttrs(current)["attributes"])
	return types.ObjectValueMust(azureSecretAttributesAttrTypes, map[string]attr.Value{
		"enabled":         enabled,
		"activation_date": azureSecretKeptDate(currentAttrs, "activation_date"),
		"expiration_date": azureSecretKeptDate(currentAttrs, "expiration_date"),
	})
}

// azureSecretKeptDate returns a date from the current attributes, null when it is missing or unknown.
func azureSecretKeptDate(current map[string]attr.Value, name string) types.String {
	date := attrString(current, name)
	if date.IsUnknown() {
		return types.StringNull()
	}
	return date
}
