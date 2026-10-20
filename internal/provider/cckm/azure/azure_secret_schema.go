package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureSecretTFSDK is the Terraform model for the ciphertrust_azure_secret resource.
type AzureSecretTFSDK struct {
	// Inputs
	Name        types.String `tfsdk:"name"`
	VaultID     types.String `tfsdk:"vault_id"`
	AzureParams types.Object `tfsdk:"azure_params"`
	// RestoreSecret restores a purged secret from its backup instead of creating a new one.
	RestoreSecret *AzureRestoreSecretTFSDK `tfsdk:"restore_secret"`

	// Computed - CipherTrust Manager
	ID                       types.String `tfsdk:"id"`
	URI                      types.String `tfsdk:"uri"`
	Account                  types.String `tfsdk:"account"`
	CreatedAt                types.String `tfsdk:"created_at"`
	UpdatedAt                types.String `tfsdk:"updated_at"`
	SyncedAt                 types.String `tfsdk:"synced_at"`
	CreatedBy                types.String `tfsdk:"created_by"`
	ModifiedBy               types.String `tfsdk:"modified_by"`
	Status                   types.String `tfsdk:"status"`
	Version                  types.String `tfsdk:"version"`
	VersionCount             types.Int64  `tfsdk:"version_count"`
	Deleted                  types.Bool   `tfsdk:"deleted"`
	Gone                     types.Bool   `tfsdk:"gone"`
	SecretSoftDeletedInAzure types.Bool   `tfsdk:"secret_soft_deleted_in_azure"`
	Backup                   types.String `tfsdk:"backup"`
	BackupAt                 types.String `tfsdk:"backup_at"`

	// Computed - Azure
	CloudName         types.String `tfsdk:"cloud_name"`
	Region            types.String `tfsdk:"region"`
	Tenant            types.String `tfsdk:"tenant"`
	VaultName         types.String `tfsdk:"vault_name"`
	SoftDeleteEnabled types.Bool   `tfsdk:"soft_delete_enabled"`
	AzureCreatedAt    types.String `tfsdk:"azure_created_at"`
	AzureUpdatedAt    types.String `tfsdk:"azure_updated_at"`
}

// AzureRestoreSecretTFSDK is the restore_secret block.
type AzureRestoreSecretTFSDK struct {
	SecretID types.String `tfsdk:"secret_id"`
}

var (
	azureSecretAttributesAttrTypes = map[string]attr.Type{
		"enabled":         types.BoolType,
		"activation_date": types.StringType,
		"expiration_date": types.StringType,
	}
	azureSecretParamsAttrTypes = map[string]attr.Type{
		"value":            types.StringType,
		"content_type":     types.StringType,
		"tags":             types.MapType{ElemType: types.StringType},
		"attributes":       types.ObjectType{AttrTypes: azureSecretAttributesAttrTypes},
		"secret_id":        types.StringType,
		"recoverable_days": types.Int64Type,
		"recovery_level":   types.StringType,
	}
)
