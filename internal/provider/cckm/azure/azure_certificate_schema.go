package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureCertificateTFSDK is the Terraform model for the ciphertrust_azure_certificate resource.
// A certificate is created natively (azure_params.policy) or uploaded (upload_certificate).
type AzureCertificateTFSDK struct {
	// Inputs
	Name              types.String                 `tfsdk:"name"`
	VaultID           types.String                 `tfsdk:"vault_id"`
	AzureParams       types.Object                 `tfsdk:"azure_params"`
	UploadCertificate *AzureUploadCertificateTFSDK `tfsdk:"upload_certificate"`
	// RestoreCertificate restores a purged certificate from its backup instead of creating a new one.
	RestoreCertificate *AzureRestoreCertificateTFSDK `tfsdk:"restore_certificate"`

	// Computed - CipherTrust Manager
	ID                     types.String `tfsdk:"id"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	SyncedAt               types.String `tfsdk:"synced_at"`
	RotatedAt              types.String `tfsdk:"rotated_at"`
	Status                 types.String `tfsdk:"status"`
	Version                types.String `tfsdk:"version"`
	VersionCount           types.Int64  `tfsdk:"version_count"`
	Operation              types.String `tfsdk:"operation"`
	OperationError         types.String `tfsdk:"operation_error"`
	Error                  types.String `tfsdk:"error"`
	Deleted                types.Bool   `tfsdk:"deleted"`
	Gone                   types.Bool   `tfsdk:"gone"`
	CertSoftDeletedInAzure types.Bool   `tfsdk:"cert_soft_deleted_in_azure"`
	CertMaterialOrigin     types.String `tfsdk:"cert_material_origin"`
	CertSource             types.String `tfsdk:"cert_source"`
	Backup                 types.String `tfsdk:"backup"`
	BackupAt               types.String `tfsdk:"backup_at"`

	// Computed - Azure
	CloudName         types.String `tfsdk:"cloud_name"`
	Region            types.String `tfsdk:"region"`
	Tenant            types.String `tfsdk:"tenant"`
	VaultName         types.String `tfsdk:"vault_name"`
	SoftDeleteEnabled types.Bool   `tfsdk:"soft_delete_enabled"`
	AzureCreatedAt    types.String `tfsdk:"azure_created_at"`
	AzureUpdatedAt    types.String `tfsdk:"azure_updated_at"`
	AzureExpireAt     types.String `tfsdk:"azure_expire_at"`
	Cert              types.String `tfsdk:"cert"`
	Cid               types.String `tfsdk:"cid"`
	Kid               types.String `tfsdk:"kid"`
	Sid               types.String `tfsdk:"sid"`
	Thumbprint        types.String `tfsdk:"thumbprint"`
	RecoveryLevel     types.String `tfsdk:"recovery_level"`
	RecoverableDays   types.Int64  `tfsdk:"recoverable_days"`
}

// AzureRestoreCertificateTFSDK is the restore_certificate block.
type AzureRestoreCertificateTFSDK struct {
	CertificateID types.String `tfsdk:"certificate_id"`
}

// AzureUploadCertificateTFSDK is the upload_certificate block.
type AzureUploadCertificateTFSDK struct {
	SourceCertID       types.String `tfsdk:"source_cert_id"`
	CaID               types.String `tfsdk:"ca_id"`
	Certificate        types.String `tfsdk:"certificate"`
	PrivateKeyPem      types.String `tfsdk:"private_key_pem"`
	PrivateKeyPassword types.String `tfsdk:"private_key_password"`
}

var (
	azureCertIssuerAttrTypes = map[string]attr.Type{
		"name":              types.StringType,
		"certificate_type":  types.StringType,
		"cert_transparency": types.BoolType,
	}
	azureCertKeyPropsAttrTypes = map[string]attr.Type{
		"kty":        types.StringType,
		"curve":      types.StringType,
		"exportable": types.BoolType,
		"key_size":   types.Int64Type,
		"reuse_key":  types.BoolType,
	}
	azureCertSansAttrTypes = map[string]attr.Type{
		"dns_names":            types.ListType{ElemType: types.StringType},
		"emails":               types.ListType{ElemType: types.StringType},
		"user_principal_names": types.ListType{ElemType: types.StringType},
	}
	azureCertX509PropsAttrTypes = map[string]attr.Type{
		"subject":            types.StringType,
		"enhanced_key_usage": types.ListType{ElemType: types.StringType},
		"key_usage":          types.ListType{ElemType: types.StringType},
		"validity_months":    types.Int64Type,
		"sans":               types.ObjectType{AttrTypes: azureCertSansAttrTypes},
	}
	azureCertAttributesAttrTypes = map[string]attr.Type{
		"enabled":         types.BoolType,
		"activation_date": types.StringType,
		"expiration_date": types.StringType,
	}
	azureCertSecretPropsAttrTypes = map[string]attr.Type{
		"content_type": types.StringType,
	}
	azureCertTriggerAttrTypes = map[string]attr.Type{
		"lifetime_percentage": types.Int64Type,
		"days_before_expiry":  types.Int64Type,
	}
	azureCertActionAttrTypes = map[string]attr.Type{
		"action_type": types.StringType,
	}
	azureCertLifetimeActionAttrTypes = map[string]attr.Type{
		"trigger": types.ObjectType{AttrTypes: azureCertTriggerAttrTypes},
		"action":  types.ObjectType{AttrTypes: azureCertActionAttrTypes},
	}
	azureCertPolicyAttrTypes = map[string]attr.Type{
		"issuer":           types.ObjectType{AttrTypes: azureCertIssuerAttrTypes},
		"key_props":        types.ObjectType{AttrTypes: azureCertKeyPropsAttrTypes},
		"x509_props":       types.ObjectType{AttrTypes: azureCertX509PropsAttrTypes},
		"attributes":       types.ObjectType{AttrTypes: azureCertAttributesAttrTypes},
		"lifetime_actions": types.ListType{ElemType: types.ObjectType{AttrTypes: azureCertLifetimeActionAttrTypes}},
		"secret_props":     types.ObjectType{AttrTypes: azureCertSecretPropsAttrTypes},
	}
	azureCertParamsAttrTypes = map[string]attr.Type{
		"tags":   types.MapType{ElemType: types.StringType},
		"policy": types.ObjectType{AttrTypes: azureCertPolicyAttrTypes},
	}
)
