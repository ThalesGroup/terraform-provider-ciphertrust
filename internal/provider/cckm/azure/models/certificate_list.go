package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureCertificateListEntryTFSDK is the Terraform state for one certificate entry in the
// ciphertrust_azure_certificate_list data source.
type AzureCertificateListEntryTFSDK struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	VaultID                types.String `tfsdk:"vault_id"`
	KeyVault               types.String `tfsdk:"key_vault"`
	CloudName              types.String `tfsdk:"cloud_name"`
	Region                 types.String `tfsdk:"region"`
	Tenant                 types.String `tfsdk:"tenant"`
	Status                 types.String `tfsdk:"status"`
	Version                types.String `tfsdk:"version"`
	VersionCount           types.Int64  `tfsdk:"version_count"`
	Deleted                types.Bool   `tfsdk:"deleted"`
	Gone                   types.Bool   `tfsdk:"gone"`
	CertSoftDeletedInAzure types.Bool   `tfsdk:"cert_soft_deleted_in_azure"`
	SoftDeleteEnabled      types.Bool   `tfsdk:"soft_delete_enabled"`
	CertMaterialOrigin     types.String `tfsdk:"cert_material_origin"`
	CertSource             types.String `tfsdk:"cert_source"`
	Backup                 types.String `tfsdk:"backup"`
	BackupAt               types.String `tfsdk:"backup_at"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	SyncedAt               types.String `tfsdk:"synced_at"`
	RotatedAt              types.String `tfsdk:"rotated_at"`
	AzureCreatedAt         types.String `tfsdk:"azure_created_at"`
	AzureUpdatedAt         types.String `tfsdk:"azure_updated_at"`
	AzureExpireAt          types.String `tfsdk:"azure_expire_at"`
	Cert                   types.String `tfsdk:"cert"`
	Cid                    types.String `tfsdk:"cid"`
	Kid                    types.String `tfsdk:"kid"`
	Sid                    types.String `tfsdk:"sid"`
	Thumbprint             types.String `tfsdk:"thumbprint"`
	RecoveryLevel          types.String `tfsdk:"recovery_level"`
	RecoverableDays        types.Int64  `tfsdk:"recoverable_days"`
	AzureParams            types.Object `tfsdk:"azure_params"`
}

// AzureCertificateListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_certificate_list data source.
type AzureCertificateListTFSDK struct {
	Filters      types.Map                        `tfsdk:"filters"`
	Matched      types.Int64                      `tfsdk:"matched"`
	Certificates []AzureCertificateListEntryTFSDK `tfsdk:"certificates"`
}
