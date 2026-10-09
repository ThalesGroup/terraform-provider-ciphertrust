package models

import (
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AzureVaultAclTFSDK is the Terraform state for the ciphertrust_azure_acl resource.
type AzureVaultAclTFSDK struct {
	ID      types.String `tfsdk:"id"`
	VaultID types.String `tfsdk:"vault_id"`
	acls.AclTFSDK
}

// AzureVaultInputJSON is the request body for the get-vaults API.
type AzureVaultInputJSON struct {
	Connection     string  `json:"connection"`
	SubscriptionID string  `json:"subscription_id"`
	Limit          int     `json:"limit"`
	NextLink       *string `json:"nextLink"`
}

// AzureSkuJSON is the vault SKU nested inside AzureVaultPropertiesJSON.
type AzureSkuJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// AzureVaultPropertiesJSON maps the properties object in the get-vaults API response.
// All field names use the Azure camelCase JSON keys as returned by the API.
type AzureVaultPropertiesJSON struct {
	TenantID                     string       `json:"tenantId"`
	Sku                          AzureSkuJSON `json:"sku"`
	VaultURI                     string       `json:"vaultUri"`
	EnabledForDeployment         bool         `json:"enabledForDeployment"`
	EnabledForDiskEncryption     bool         `json:"enabledForDiskEncryption"`
	EnabledForTemplateDeployment bool         `json:"enabledForTemplateDeployment"`
	EnableSoftDelete             bool         `json:"enableSoftDelete"`
	CreateMode                   string       `json:"createMode"`
	EnablePurgeProtection        bool         `json:"enablePurgeProtection"`
	SoftDeleteRetentionInDays    int32        `json:"softDeleteRetentionInDays"`
	EnableRbacAuthorization      bool         `json:"enableRbacAuthorization"`
}

// AzureVaultDataJSON is one entry in the vaults array returned by the get-vaults API.
type AzureVaultDataJSON struct {
	Name         string                   `json:"name"`
	AzureVaultID string                   `json:"azure_vault_id"`
	Type         string                   `json:"type"`
	Location     string                   `json:"location"`
	Tags         map[string]string        `json:"tags"`
	Properties   AzureVaultPropertiesJSON `json:"properties"`
}

// AzureVaultOutputJSON is the top-level response envelope from the get-vaults API.
type AzureVaultOutputJSON struct {
	Vaults         []AzureVaultDataJSON `json:"vaults"`
	Connection     string               `json:"connection"`
	SubscriptionID string               `json:"subscription_id"`
	NextLink       *string              `json:"nextLink"`
}

// AzureSkuTFSDK is the Terraform state for the sku nested attribute inside
// vault_properties. Uses a non-pointer value type to avoid panics with
// schema.SingleNestedAttribute on resp.State.Set.
type AzureSkuTFSDK struct {
	Family types.String `tfsdk:"family"`
	Name   types.String `tfsdk:"name"`
}

// AzureVaultPropertiesTFSDK is the Terraform state for the vault_properties
// nested attribute.
type AzureVaultPropertiesTFSDK struct {
	TenantID                     types.String  `tfsdk:"tenant_id"`
	Sku                          AzureSkuTFSDK `tfsdk:"sku"`
	VaultURI                     types.String  `tfsdk:"vault_uri"`
	EnabledForDeployment         types.Bool    `tfsdk:"enabled_for_deployment"`
	EnabledForDiskEncryption     types.Bool    `tfsdk:"enabled_for_disk_encryption"`
	EnabledForTemplateDeployment types.Bool    `tfsdk:"enabled_for_template_deployment"`
	EnableSoftDelete             types.Bool    `tfsdk:"enable_soft_delete"`
	CreateMode                   types.String  `tfsdk:"create_mode"`
	EnablePurgeProtection        types.Bool    `tfsdk:"enable_purge_protection"`
	SoftDeleteRetentionInDays    types.Int64   `tfsdk:"soft_delete_retention_in_days"`
	EnableRbacAuthorization      types.Bool    `tfsdk:"enable_rbac_authorization"`
}

// AzureVaultDetailTFSDK is the Terraform state for a single vault entry in the
// vaults map returned by the ciphertrust_azure_vault_details data source.
type AzureVaultDetailTFSDK struct {
	Name            types.String              `tfsdk:"name"`
	AzureVaultID    types.String              `tfsdk:"azure_vault_id"`
	VaultType       types.String              `tfsdk:"vault_type"`
	Location        types.String              `tfsdk:"location"`
	Tags            types.Map                 `tfsdk:"tags"`
	VaultProperties AzureVaultPropertiesTFSDK `tfsdk:"vault_properties"`
}

// AzureVaultDetailsTFSDK is the top-level Terraform state for the
// ciphertrust_azure_vault_details data source.
type AzureVaultDetailsTFSDK struct {
	ConnectionID   types.String                     `tfsdk:"connection_id"`
	SubscriptionID types.String                     `tfsdk:"subscription_id"`
	ManagedHSMs    types.Bool                       `tfsdk:"managed_hsms"`
	Vaults         map[string]AzureVaultDetailTFSDK `tfsdk:"vaults"`
}

// --- Types for the ciphertrust_azure_vault resource ---

// AzureAddVaultPayloadJSON is the request body for POST /azure/add-vaults.
type AzureAddVaultPayloadJSON struct {
	SubscriptionID      string               `json:"subscription_id"`
	Vaults              []AzureVaultDataJSON `json:"vaults"`
	Connection          string               `json:"connection"`
	CloudKeyBackupLimit *int                 `json:"cloud_key_backup_limit,omitempty"`
}

// AzureVaultListPageJSON is the list-response envelope from GET /azure/vaults.
type AzureVaultListPageJSON struct {
	Total     int64                     `json:"total"`
	Resources []AzureVaultListEntryJSON `json:"resources"`
}

// AzureVaultListEntryJSON is one entry in the GET /azure/vaults response.
type AzureVaultListEntryJSON struct {
	ID               string                   `json:"id"`
	AzureName        string                   `json:"azure_name"`
	AzureVaultID     string                   `json:"azure_vault_id"`
	CloudName        string                   `json:"cloud_name"`
	Connection       string                   `json:"connection"`
	CreatedAt        string                   `json:"createdAt"`
	Location         string                   `json:"location"`
	SubscriptionID   string                   `json:"subscription_id"`
	SubscriptionName string                   `json:"subscription_name"`
	SyncedAt         string                   `json:"synced_at"`
	UpdatedAt        string                   `json:"updatedAt"`
	URI              string                   `json:"uri"`
	VaultType        string                   `json:"type"`
	Properties       AzureVaultPropertiesJSON `json:"properties"`
	Tags             map[string]string        `json:"tags"`
}

// AzureVaultListEntryTFSDK is the Terraform state for one vault entry in the
// ciphertrust_azure_vault_list data source.
type AzureVaultListEntryTFSDK struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Acls             types.Set    `tfsdk:"acls"`
	AzureVaultID     types.String `tfsdk:"azure_vault_id"`
	CloudName        types.String `tfsdk:"cloud_name"`
	Connection       types.String `tfsdk:"connection"`
	CreatedAt        types.String `tfsdk:"created_at"`
	Location         types.String `tfsdk:"location"`
	SubscriptionID   types.String `tfsdk:"subscription_id"`
	SubscriptionName types.String `tfsdk:"subscription_name"`
	SyncedAt         types.String `tfsdk:"synced_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	URI              types.String `tfsdk:"uri"`
	VaultType        types.String `tfsdk:"vault_type"`
	VaultProperties  types.Object `tfsdk:"vault_properties"`
	Tags             types.Map    `tfsdk:"tags"`
}

// AzureVaultListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_vault_list data source.
type AzureVaultListTFSDK struct {
	Filters types.Map                  `tfsdk:"filters"`
	Matched types.Int64                `tfsdk:"matched"`
	Vaults  []AzureVaultListEntryTFSDK `tfsdk:"vaults"`
}

// AzureUpdateVaultPayloadJSON is the request body for PATCH /azure/vaults/:id.
type AzureUpdateVaultPayloadJSON struct {
	Connection          string `json:"connection"`
	CloudKeyBackupLimit *int   `json:"cloud_key_backup_limit,omitempty"`
}

// AzureVaultTFSDK is the Terraform state for the ciphertrust_azure_vault resource.
type AzureVaultTFSDK struct {
	// Required user inputs
	Name           types.String `tfsdk:"name"`
	ConnectionID   types.String `tfsdk:"connection_id"`
	SubscriptionID types.String `tfsdk:"subscription_id"`

	// Optional user inputs
	CloudKeyBackupLimit types.Int64  `tfsdk:"cloud_key_backup_limit"`
	VaultDetails        types.Object `tfsdk:"vault_details"`

	// Computed
	ID               types.String `tfsdk:"id"`
	Account          types.String `tfsdk:"account"`
	Acls             types.Set    `tfsdk:"acls"`
	AzureVaultID     types.String `tfsdk:"azure_vault_id"`
	CckmVaultName    types.String `tfsdk:"cckm_vault_name"`
	CloudName        types.String `tfsdk:"cloud_name"`
	ConnectionName   types.String `tfsdk:"connection_name"`
	CreatedAt        types.String `tfsdk:"created_at"`
	Labels           types.Map    `tfsdk:"labels"`
	Location         types.String `tfsdk:"location"`
	SubscriptionName types.String `tfsdk:"subscription_name"`
	SyncedAt         types.String `tfsdk:"synced_at"`
	Tags             types.Map    `tfsdk:"tags"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	URI              types.String `tfsdk:"uri"`
	VaultProperties  types.Object `tfsdk:"vault_properties"`
	VaultType        types.String `tfsdk:"vault_type"`
}
