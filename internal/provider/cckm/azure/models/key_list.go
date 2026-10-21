package models

import "github.com/hashicorp/terraform-plugin-framework/types"

// AzureKeyListPageJSON is the list-response envelope from GET /azure/keys.
type AzureKeyListPageJSON struct {
	Total     int64                   `json:"total"`
	Resources []AzureKeyListEntryJSON `json:"resources"`
}

// AzureKeyListEntryJSON is one entry in the GET /azure/keys response.
type AzureKeyListEntryJSON struct {
	ID                string                `json:"id"`
	KeyName           string                `json:"key_name"`
	KeyVault          string                `json:"key_vault"`
	KeyVaultID        string                `json:"key_vault_id"`
	CloudName         string                `json:"cloud_name"`
	Region            string                `json:"region"`
	Status            string                `json:"status"`
	Version           string                `json:"version"`
	KeySize           int64                 `json:"key_size"`
	KeyMaterialOrigin string                `json:"key_material_origin"`
	Tenant            string                `json:"tenant"`
	Gone              bool                  `json:"gone"`
	Deleted           bool                  `json:"deleted"`
	CreatedAt         string                `json:"createdAt"`
	UpdatedAt         string                `json:"updatedAt"`
	SyncedAt          string                `json:"syncedAt"`
	AzureParam        AzureKeyListParamJSON `json:"azure_param"`

	RotatedAt             string `json:"rotated_at"`
	AzureCreatedAt        string `json:"azure_created_at"`
	AzureUpdatedAt        string `json:"azure_updated_at"`
	AzureExpireAt         string `json:"azure_expire_at"`
	CreatedBy             string `json:"created_by"`
	ModifiedBy            string `json:"modified_by"`
	VersionDeletedInAzure bool   `json:"version_deleted_in_azure"`
	KeySource             string `json:"key_source"`
	LocalKeyID            string `json:"local_key_id"`
	Operation             string `json:"operation"`
	OperationError        string `json:"operation_error"`
	AvailableInKeyVault   string `json:"available_in_key_vault"`
	PkID                  string `json:"pk_id"`
}

// AzureKeyListParamJSON is the azure_param object of a listed key.
type AzureKeyListParamJSON struct {
	Key        AzureKeyListKeyJSON        `json:"key"`
	Attributes AzureKeyListAttributesJSON `json:"attributes"`
}

// AzureKeyListKeyJSON is azure_param.key of a listed key.
type AzureKeyListKeyJSON struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
}

// AzureKeyListAttributesJSON is azure_param.attributes of a listed key.
type AzureKeyListAttributesJSON struct {
	Enabled bool `json:"enabled"`
}

// AzureKeyListEntryTFSDK is the Terraform state for one key entry in the
// ciphertrust_azure_key_list data source.
type AzureKeyListEntryTFSDK struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	VaultName         types.String `tfsdk:"vault_name"`
	VaultID           types.String `tfsdk:"vault_id"`
	CloudName         types.String `tfsdk:"cloud_name"`
	Region            types.String `tfsdk:"region"`
	Status            types.String `tfsdk:"status"`
	Version           types.String `tfsdk:"version"`
	Kid               types.String `tfsdk:"kid"`
	Kty               types.String `tfsdk:"kty"`
	Curve             types.String `tfsdk:"curve"`
	KeySize           types.Int64  `tfsdk:"key_size"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	KeyMaterialOrigin types.String `tfsdk:"key_material_origin"`
	Tenant            types.String `tfsdk:"tenant"`
	Gone              types.Bool   `tfsdk:"gone"`
	Deleted           types.Bool   `tfsdk:"deleted"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
	SyncedAt          types.String `tfsdk:"synced_at"`

	RotatedAt             types.String `tfsdk:"rotated_at"`
	AzureCreatedAt        types.String `tfsdk:"azure_created_at"`
	AzureUpdatedAt        types.String `tfsdk:"azure_updated_at"`
	AzureExpireAt         types.String `tfsdk:"azure_expire_at"`
	CreatedBy             types.String `tfsdk:"created_by"`
	ModifiedBy            types.String `tfsdk:"modified_by"`
	VersionDeletedInAzure types.Bool   `tfsdk:"version_deleted_in_azure"`
	KeySource             types.String `tfsdk:"key_source"`
	LocalKeyID            types.String `tfsdk:"local_key_id"`
	Operation             types.String `tfsdk:"operation"`
	OperationError        types.String `tfsdk:"operation_error"`
	AvailableInKeyVault   types.String `tfsdk:"available_in_key_vault"`
	PkID                  types.String `tfsdk:"pk_id"`
}

// AzureKeyListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_key_list data source.
type AzureKeyListTFSDK struct {
	Filters types.Map                `tfsdk:"filters"`
	Matched types.Int64              `tfsdk:"matched"`
	Keys    []AzureKeyListEntryTFSDK `tfsdk:"keys"`
}
