package models

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureKeyTFSDK is the Terraform model for the ciphertrust_azure_key resource. A key is created
// natively, uploaded (upload_key) or restored (restore_key).
type AzureKeyTFSDK struct {
	// Inputs
	VaultID       types.String `tfsdk:"vault_id"`
	Name          types.String `tfsdk:"name"`
	AzureParams   types.Object `tfsdk:"azure_params"`
	Exportable    types.Bool   `tfsdk:"exportable"`
	ReleasePolicy types.String `tfsdk:"release_policy"`

	// RestoreKey restores an existing key instead of creating a new one.
	RestoreKey *AzureRestoreKeyTFSDK `tfsdk:"restore_key"`

	// UploadKey uploads key material instead of creating a new key.
	UploadKey *AzureUploadKeyTFSDK `tfsdk:"upload_key"`

	// EnableAutoRotation is applied by Update only. It is not allowed when a key is created.
	EnableAutoRotation *EnableAutoRotationTFSDK `tfsdk:"enable_auto_rotation"`

	// EnableAutoBackup is applied by Update only. It is not allowed when a key is created.
	EnableAutoBackup *EnableAutoBackupTFSDK `tfsdk:"enable_auto_backup"`

	// Computed
	BackupConfig          types.Map    `tfsdk:"backup_config"`
	ID                    types.String `tfsdk:"id"`
	Account               types.String `tfsdk:"account"`
	Backup                types.String `tfsdk:"backup"`
	BackupAt              types.String `tfsdk:"backup_at"`
	CloudName             types.String `tfsdk:"cloud_name"`
	CreatedAt             types.String `tfsdk:"created_at"`
	Deleted               types.Bool   `tfsdk:"deleted"`
	KeyMaterialOrigin     types.String `tfsdk:"key_material_origin"`
	KeySoftDeletedInAzure types.Bool   `tfsdk:"key_soft_deleted_in_azure"`
	Labels                types.Map    `tfsdk:"labels"`
	Region                types.String `tfsdk:"region"`
	SoftDeleteEnabled     types.Bool   `tfsdk:"soft_delete_enabled"`
	Status                types.String `tfsdk:"status"`
	SyncedAt              types.String `tfsdk:"synced_at"`
	Tenant                types.String `tfsdk:"tenant"`
	UpdatedAt             types.String `tfsdk:"updated_at"`
	Version               types.String `tfsdk:"version"`
	VersionCount          types.Int64  `tfsdk:"version_count"`
	VaultName             types.String `tfsdk:"vault_name"`
}

// AzureRestoreKeyTFSDK is the restore_key block.
type AzureRestoreKeyTFSDK struct {
	KeyID    types.String `tfsdk:"key_id"`
	BackupID types.String `tfsdk:"backup_id"`
}

// AzureUploadKeyTFSDK is the upload_key block.
type AzureUploadKeyTFSDK struct {
	SourceKeyTier types.String `tfsdk:"source_key_tier"`
	SourceKeyID   types.String `tfsdk:"source_key_id"`
	Pfx           types.String `tfsdk:"pfx"`
	PfxPassword   types.String `tfsdk:"pfx_password"`
	KekKid        types.String `tfsdk:"kek_kid"`
	Hsm           types.Bool   `tfsdk:"hsm"`

	// LocalKeyName is computed. It is the name of the CipherTrust Manager key when source_key_tier is local.
	LocalKeyName types.String `tfsdk:"local_key_name"`
}

// AzureParamsTFSDK is the azure_params block.
type AzureParamsTFSDK struct {
	Key        types.Object `tfsdk:"key"`
	Attributes types.Object `tfsdk:"attributes"`
	KeySize    types.Int64  `tfsdk:"key_size"`
	Tags       types.Map    `tfsdk:"tags"`
}

// AzureParamsKeyTFSDK is the azure_params.key block.
type AzureParamsKeyTFSDK struct {
	Kty    types.String `tfsdk:"kty"`
	Curve  types.String `tfsdk:"curve"`
	KeyOps types.List   `tfsdk:"key_ops"`
	Kid    types.String `tfsdk:"kid"`
	N      types.String `tfsdk:"n"`
	E      types.String `tfsdk:"e"`
}

// AzureParamsAttributesTFSDK is the azure_params.attributes block. Dates are UTC RFC3339 strings.
type AzureParamsAttributesTFSDK struct {
	Enabled        types.Bool   `tfsdk:"enabled"`
	ExpirationDate types.String `tfsdk:"expiration_date"`
	ActivationDate types.String `tfsdk:"activation_date"`
	RecoveryLevel  types.String `tfsdk:"recovery_level"`
	Created        types.Int64  `tfsdk:"created"`
	Updated        types.Int64  `tfsdk:"updated"`
}

// AzureParamsKeyAttrTypes are the attribute types of azure_params.key.
var AzureParamsKeyAttrTypes = map[string]attr.Type{
	"kty":     types.StringType,
	"curve":   types.StringType,
	"key_ops": types.ListType{ElemType: types.StringType},
	"kid":     types.StringType,
	"n":       types.StringType,
	"e":       types.StringType,
}

// AzureParamsAttributesAttrTypes are the attribute types of azure_params.attributes.
var AzureParamsAttributesAttrTypes = map[string]attr.Type{
	"enabled":         types.BoolType,
	"expiration_date": types.StringType,
	"activation_date": types.StringType,
	"recovery_level":  types.StringType,
	"created":         types.Int64Type,
	"updated":         types.Int64Type,
}

// AzureParamsAttrTypes are the attribute types of azure_params.
var AzureParamsAttrTypes = map[string]attr.Type{
	"key":        types.ObjectType{AttrTypes: AzureParamsKeyAttrTypes},
	"attributes": types.ObjectType{AttrTypes: AzureParamsAttributesAttrTypes},
	"key_size":   types.Int64Type,
	"tags":       types.MapType{ElemType: types.StringType},
}

// AzureKeyAttributesJSON is the attributes object of the create key request.
// Dates are Unix epoch seconds.
type AzureKeyAttributesJSON struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	NotBefore *int64 `json:"nbf,omitempty"`
	Expires   *int64 `json:"exp,omitempty"`
}

// AzureKeyParamJSON is the azure_param object of the create key request.
type AzureKeyParamJSON struct {
	KeyType    string                  `json:"kty,omitempty"`
	Curve      string                  `json:"crv,omitempty"`
	KeySize    int64                   `json:"key_size,omitempty"`
	KeyOps     []string                `json:"key_ops,omitempty"`
	Tags       map[string]string       `json:"tags,omitempty"`
	Attributes *AzureKeyAttributesJSON `json:"attributes,omitempty"`
}

// AzureCreateKeyPayloadJSON is the request body for POST /azure/keys.
type AzureCreateKeyPayloadJSON struct {
	KeyName       string                 `json:"key_name"`
	KeyVault      string                 `json:"key_vault"`
	AzureParam    AzureKeyParamJSON      `json:"azure_param"`
	Exportable    *bool                  `json:"exportable,omitempty"`
	ReleasePolicy map[string]interface{} `json:"release_policy,omitempty"`
}

// AzureUploadKeyAttributesJSON is the azure_param.attributes object of the upload key request.
type AzureUploadKeyAttributesJSON struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	NotBefore *int64 `json:"nbf,omitempty"`
	Expires   *int64 `json:"exp,omitempty"`
}

// AzureUploadKeyParamJSON is the azure_param object of the upload key request. The upload API does not
// take kty, crv or key_size. Hsm must be true to create an HSM key, otherwise Azure creates a software key.
type AzureUploadKeyParamJSON struct {
	Hsm        *bool                         `json:"hsm,omitempty"`
	KeyOps     []string                      `json:"key_ops,omitempty"`
	Tags       map[string]string             `json:"tags,omitempty"`
	Attributes *AzureUploadKeyAttributesJSON `json:"attributes,omitempty"`
}

// AzureUploadKeyPayloadJSON is the request body for POST /azure/upload-key.
// exportable and release_policy are only set when the key is exportable.
type AzureUploadKeyPayloadJSON struct {
	KeyName            string                  `json:"key_name"`
	KeyVault           string                  `json:"key_vault"`
	AzureParam         AzureUploadKeyParamJSON `json:"azure_param"`
	SourceKeyTier      string                  `json:"source_key_tier"`
	LocalKeyIdentifier string                  `json:"local_key_identifier"`
	PFX                string                  `json:"pfx"`
	Password           string                  `json:"password"`
	KekKID             string                  `json:"kek_kid"`
	ReleasePolicy      map[string]interface{}  `json:"release_policy"`
	Exportable         *bool                   `json:"exportable"`
}

// EnableAutoRotationTFSDK is the enable_auto_rotation block.
type EnableAutoRotationTFSDK struct {
	JobConfigID   types.String `tfsdk:"job_config_id"`
	KeySource     types.String `tfsdk:"key_source"`
	KeyType       types.String `tfsdk:"key_type"`
	KeySize       types.Int64  `tfsdk:"key_size"`
	ECName        types.String `tfsdk:"ec_name"`
	EnableKey     types.Bool   `tfsdk:"enable_key"`
	ReleasePolicy types.String `tfsdk:"release_policy"`
}

// AzureEnableRotationPayloadJSON is the request body for POST /azure/keys/:id/enable-rotation-job.
// auto_rotate_enable_key is always sent so that false is not left out.
type AzureEnableRotationPayloadJSON struct {
	JobConfigID             string          `json:"job_config_id"`
	AutoRotateKeySource     string          `json:"auto_rotate_key_source"`
	AutoRotateKeyType       string          `json:"auto_rotate_key_type"`
	AutoRotateKeySize       int64           `json:"auto_rotate_key_size,omitempty"`
	AutoRotateECName        string          `json:"auto_rotate_ec_name,omitempty"`
	AutoRotateEnableKey     bool            `json:"auto_rotate_enable_key"`
	AutoRotateReleasePolicy json.RawMessage `json:"auto_rotate_release_policy,omitempty"`
}

// EnableAutoBackupTFSDK is the enable_auto_backup block.
type EnableAutoBackupTFSDK struct {
	JobConfigID types.String `tfsdk:"job_config_id"`
}

// AzureEnableBackupPayloadJSON is the request body for POST /azure/keys/:id/enable-backup-job.
type AzureEnableBackupPayloadJSON struct {
	BackupJobConfigID string `json:"backup_job_config_id"`
}

// AzureRestoreKeyPayloadJSON is the request body for POST /azure/keys/:id/restore.
type AzureRestoreKeyPayloadJSON struct {
	KeyVault              string `json:"key_vault"`
	AzureCloudKeyBackupID string `json:"azure_cloud_key_backup_id,omitempty"`
}
