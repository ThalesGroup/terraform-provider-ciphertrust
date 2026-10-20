package models

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureSecretListPageJSON is the list-response envelope from GET /azure/secrets.
type AzureSecretListPageJSON struct {
	Total     int64             `json:"total"`
	Resources []json.RawMessage `json:"resources"`
}

// AzureSecretListEntryTFSDK is the Terraform state for one secret entry in the
// ciphertrust_azure_secret_list data source. The secret value is never part of it.
type AzureSecretListEntryTFSDK struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	VaultID                  types.String `tfsdk:"vault_id"`
	VaultName                types.String `tfsdk:"vault_name"`
	CloudName                types.String `tfsdk:"cloud_name"`
	Region                   types.String `tfsdk:"region"`
	Tenant                   types.String `tfsdk:"tenant"`
	Status                   types.String `tfsdk:"status"`
	Version                  types.String `tfsdk:"version"`
	VersionCount             types.Int64  `tfsdk:"version_count"`
	Deleted                  types.Bool   `tfsdk:"deleted"`
	Gone                     types.Bool   `tfsdk:"gone"`
	SecretSoftDeletedInAzure types.Bool   `tfsdk:"secret_soft_deleted_in_azure"`
	SoftDeleteEnabled        types.Bool   `tfsdk:"soft_delete_enabled"`
	Backup                   types.String `tfsdk:"backup"`
	BackupAt                 types.String `tfsdk:"backup_at"`
	CreatedAt                types.String `tfsdk:"created_at"`
	UpdatedAt                types.String `tfsdk:"updated_at"`
	SyncedAt                 types.String `tfsdk:"synced_at"`
	AzureCreatedAt           types.String `tfsdk:"azure_created_at"`
	AzureUpdatedAt           types.String `tfsdk:"azure_updated_at"`
	SecretID                 types.String `tfsdk:"secret_id"`
	ContentType              types.String `tfsdk:"content_type"`
	Enabled                  types.Bool   `tfsdk:"enabled"`
	RecoverableDays          types.Int64  `tfsdk:"recoverable_days"`
	RecoveryLevel            types.String `tfsdk:"recovery_level"`
	Tags                     types.String `tfsdk:"tags"`
}

// AzureSecretListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_secret_list data source.
type AzureSecretListTFSDK struct {
	Filters types.Map                   `tfsdk:"filters"`
	Matched types.Int64                 `tfsdk:"matched"`
	Secrets []AzureSecretListEntryTFSDK `tfsdk:"secrets"`
}
