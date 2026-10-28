package models

import "github.com/hashicorp/terraform-plugin-framework/types"

// AzureKeyPitBackupListPageJSON is the list-response envelope from GET /azure/keys/{id}/backups.
type AzureKeyPitBackupListPageJSON struct {
	Total     int64                            `json:"total"`
	Resources []AzureKeyPitBackupListEntryJSON `json:"resources"`
}

// AzureKeyPitBackupListEntryJSON is one entry in the GET /azure/keys/{id}/backups response.
type AzureKeyPitBackupListEntryJSON struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Type             string `json:"type"`
	Backup           string `json:"backup"`
	KeyName          string `json:"key_name"`
	KeyVault         string `json:"key_vault"`
	VaultName        string `json:"vault_name"`
	SubscriptionID   string `json:"subscription_id"`
	SubscriptionName string `json:"subscription_name"`
	Region           string `json:"region"`
	CloudName        string `json:"cloud_name"`
	Tenant           string `json:"tenant"`
	Gone             bool   `json:"gone"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
}

// AzureKeyPitBackupListEntryTFSDK is the Terraform state for one backup entry in the
// ciphertrust_azure_key_pit_backup_list data source.
type AzureKeyPitBackupListEntryTFSDK struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	Type             types.String `tfsdk:"type"`
	Backup           types.String `tfsdk:"backup"`
	KeyName          types.String `tfsdk:"key_name"`
	KeyVault         types.String `tfsdk:"key_vault"`
	VaultName        types.String `tfsdk:"vault_name"`
	SubscriptionID   types.String `tfsdk:"subscription_id"`
	SubscriptionName types.String `tfsdk:"subscription_name"`
	Region           types.String `tfsdk:"region"`
	CloudName        types.String `tfsdk:"cloud_name"`
	Tenant           types.String `tfsdk:"tenant"`
	Gone             types.Bool   `tfsdk:"gone"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
}

// AzureKeyPitBackupListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_key_pit_backup_list data source.
type AzureKeyPitBackupListTFSDK struct {
	KeyID   types.String                      `tfsdk:"key_id"`
	Filters types.Map                         `tfsdk:"filters"`
	Matched types.Int64                       `tfsdk:"matched"`
	Backups []AzureKeyPitBackupListEntryTFSDK `tfsdk:"backups"`
}
