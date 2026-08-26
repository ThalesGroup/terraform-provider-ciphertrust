package azure

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const (
	URL_AZURE_GET_SUBSCRIPTIONS = "/api/v1/cckm/azure/get-subscriptions"
	URL_AZURE_GET_VAULTS        = "/api/v1/cckm/azure/get-vaults"
	URL_AZURE_GET_MANAGED_HSMS  = "/api/v1/cckm/azure/get-managed-hsms"
	URL_AZURE_ADD_VAULTS        = "/api/v1/cckm/azure/add-vaults"
	URL_AZURE_VAULTS            = "/api/v1/cckm/azure/vaults"
)

// AzureSkuTFSDK holds SKU details for an Azure Key Vault.
// Must be a value type (not pointer) for Plugin Framework SingleNestedAttribute.
type AzureSkuTFSDK struct {
	Family types.String `tfsdk:"family"`
	Name   types.String `tfsdk:"name"`
}

// AzureVaultAclTFSDK represents one ACL entry for an Azure vault (group + allow_list).
type AzureVaultAclTFSDK struct {
	Group     types.String `tfsdk:"group"`
	AllowList types.List   `tfsdk:"allow_list"`
}

// azureVaultAclJSON is the wire format for the update-acls API call.
type azureVaultAclJSON struct {
	Group     string   `json:"group"`
	AllowList []string `json:"allow_list"`
}

// azureVaultAclAttrTypes defines the element type for the acls Set.
var azureVaultAclAttrTypes = map[string]attr.Type{
	"group":      types.StringType,
	"allow_list": types.ListType{ElemType: types.StringType},
}

// azureVaultAclElemType is the types.ObjectType for a single ACL entry.
var azureVaultAclElemType = types.ObjectType{AttrTypes: azureVaultAclAttrTypes}

// AzureVaultTFSDK is the Terraform state model for ciphertrust_azure_vault.
type AzureVaultTFSDK struct {
	ID                           types.String   `tfsdk:"id"`
	URI                          types.String   `tfsdk:"uri"`
	Name                         types.String   `tfsdk:"name"`
	ConnectionID                 types.String   `tfsdk:"connection_id"`
	ConnectionName               types.String   `tfsdk:"connection_name"`
	ManagedHsm                   types.Bool     `tfsdk:"managed_hsm"`
	SubscriptionID               types.String   `tfsdk:"subscription_id"`
	Azure                        types.String   `tfsdk:"azure"`
	AzureVaultID                 types.String   `tfsdk:"azure_vault_id"`
	AzureName                    types.String   `tfsdk:"azure_name"`
	CloudName                    types.String   `tfsdk:"cloud_name"`
	Location                     types.String   `tfsdk:"location"`
	Type                         types.String   `tfsdk:"type"`
	SubscriptionName             types.String   `tfsdk:"subscription_name"`
	Account                      types.String   `tfsdk:"account"`
	Application                  types.String   `tfsdk:"application"`
	DevAccount                   types.String   `tfsdk:"dev_account"`
	CreatedAt                    types.String   `tfsdk:"created_at"`
	UpdatedAt                    types.String   `tfsdk:"updated_at"`
	Tags                         types.Map      `tfsdk:"tags"`
	Labels                       types.Map      `tfsdk:"labels"`
	TenantID                     types.String   `tfsdk:"tenant_id"`
	VaultURI                     types.String   `tfsdk:"vault_uri"`
	EnabledForDeployment         types.Bool     `tfsdk:"enabled_for_deployment"`
	EnabledForDiskEncryption     types.Bool     `tfsdk:"enabled_for_disk_encryption"`
	EnabledForTemplateDeployment types.Bool     `tfsdk:"enabled_for_template_deployment"`
	EnableSoftDelete             types.Bool     `tfsdk:"enable_soft_delete"`
	CreateMode                   types.String   `tfsdk:"create_mode"`
	EnablePurgeProtection        types.Bool     `tfsdk:"enable_purge_protection"`
	SoftDeleteRetentionInDays    types.Int64    `tfsdk:"soft_delete_retention_in_days"`
	EnableRbacAuthorization      types.Bool     `tfsdk:"enable_rbac_authorization"`
	Sku                          AzureSkuTFSDK `tfsdk:"sku"`
	CloudKeyBackupLimit          types.Int64    `tfsdk:"cloud_key_backup_limit"`
	Acls                         types.Set      `tfsdk:"acls"`
	EnableRotation               types.Bool     `tfsdk:"enable_rotation"`
	RotationJobParams            types.String   `tfsdk:"rotation_job_params"`
}

// AzureVaultDataSourceTFSDK is the Terraform state model for a single vault in the data source.
type AzureVaultDataSourceTFSDK struct {
	ID                           types.String   `tfsdk:"id"`
	URI                          types.String   `tfsdk:"uri"`
	Name                         types.String   `tfsdk:"name"`
	ConnectionName               types.String   `tfsdk:"connection_name"`
	AzureVaultID                 types.String   `tfsdk:"azure_vault_id"`
	AzureName                    types.String   `tfsdk:"azure_name"`
	CloudName                    types.String   `tfsdk:"cloud_name"`
	Location                     types.String   `tfsdk:"location"`
	Type                         types.String   `tfsdk:"type"`
	SubscriptionID               types.String   `tfsdk:"subscription_id"`
	SubscriptionName             types.String   `tfsdk:"subscription_name"`
	Account                      types.String   `tfsdk:"account"`
	Application                  types.String   `tfsdk:"application"`
	DevAccount                   types.String   `tfsdk:"dev_account"`
	CreatedAt                    types.String   `tfsdk:"created_at"`
	UpdatedAt                    types.String   `tfsdk:"updated_at"`
	Tags                         types.Map      `tfsdk:"tags"`
	Labels                       types.Map      `tfsdk:"labels"`
	TenantID                     types.String   `tfsdk:"tenant_id"`
	VaultURI                     types.String   `tfsdk:"vault_uri"`
	EnabledForDeployment         types.Bool     `tfsdk:"enabled_for_deployment"`
	EnabledForDiskEncryption     types.Bool     `tfsdk:"enabled_for_disk_encryption"`
	EnabledForTemplateDeployment types.Bool     `tfsdk:"enabled_for_template_deployment"`
	EnableSoftDelete             types.Bool     `tfsdk:"enable_soft_delete"`
	CreateMode                   types.String   `tfsdk:"create_mode"`
	EnablePurgeProtection        types.Bool     `tfsdk:"enable_purge_protection"`
	SoftDeleteRetentionInDays    types.Int64    `tfsdk:"soft_delete_retention_in_days"`
	EnableRbacAuthorization      types.Bool     `tfsdk:"enable_rbac_authorization"`
	Sku                          AzureSkuTFSDK `tfsdk:"sku"`
	CloudKeyBackupLimit          types.Int64    `tfsdk:"cloud_key_backup_limit"`
}

// AzureVaultsListDataSourceTFSDK is the Terraform state model for the ciphertrust_azure_vaults data source.
type AzureVaultsListDataSourceTFSDK struct {
	Name           types.String                `tfsdk:"name"`
	SubscriptionID types.String                `tfsdk:"subscription_id"`
	ConnectionName types.String                `tfsdk:"connection_name"`
	Resources      []AzureVaultDataSourceTFSDK `tfsdk:"resources"`
}

// hydrateAzureVaultState populates all Computed (Saved=Yes) fields from the API response.
// Write-only fields (ConnectionID, ManagedHsm, Azure, EnableRotation, RotationJobParams)
// are not touched — callers retain their prior values.
func hydrateAzureVaultState(ctx context.Context, resp string, state *AzureVaultTFSDK, diags *diag.Diagnostics) {
	state.ID             = types.StringValue(gjson.Get(resp, "id").String())
	state.URI            = types.StringValue(gjson.Get(resp, "uri").String())
	state.Account        = types.StringValue(gjson.Get(resp, "account").String())
	state.Application    = types.StringValue(gjson.Get(resp, "application").String())
	state.DevAccount     = types.StringValue(gjson.Get(resp, "devAccount").String())
	state.CreatedAt      = types.StringValue(gjson.Get(resp, "createdAt").String())
	state.UpdatedAt      = types.StringValue(gjson.Get(resp, "updatedAt").String())
	state.ConnectionName = types.StringValue(gjson.Get(resp, "connection").String())
	state.AzureVaultID   = types.StringValue(gjson.Get(resp, "azure_vault_id").String())
	state.AzureName      = types.StringValue(gjson.Get(resp, "azure_name").String())
	state.CloudName      = types.StringValue(gjson.Get(resp, "cloud_name").String())
	state.Location       = types.StringValue(gjson.Get(resp, "location").String())
	state.Type           = types.StringValue(gjson.Get(resp, "type").String())
	state.SubscriptionName        = types.StringValue(gjson.Get(resp, "subscription_name").String())
	state.CloudKeyBackupLimit     = types.Int64Value(gjson.Get(resp, "cloud_key_backup_limit").Int())
	state.TenantID                = types.StringValue(gjson.Get(resp, "properties.tenantId").String())
	state.VaultURI                = types.StringValue(gjson.Get(resp, "properties.vaultUri").String())
	state.CreateMode              = types.StringValue(gjson.Get(resp, "properties.createMode").String())
	state.EnabledForDeployment         = types.BoolValue(gjson.Get(resp, "properties.enabledForDeployment").Bool())
	state.EnabledForDiskEncryption     = types.BoolValue(gjson.Get(resp, "properties.enabledForDiskEncryption").Bool())
	state.EnabledForTemplateDeployment = types.BoolValue(gjson.Get(resp, "properties.enabledForTemplateDeployment").Bool())
	state.EnableSoftDelete             = types.BoolValue(gjson.Get(resp, "properties.enableSoftDelete").Bool())
	state.EnablePurgeProtection        = types.BoolValue(gjson.Get(resp, "properties.enablePurgeProtection").Bool())
	state.SoftDeleteRetentionInDays    = types.Int64Value(gjson.Get(resp, "properties.softDeleteRetentionInDays").Int())
	state.EnableRbacAuthorization      = types.BoolValue(gjson.Get(resp, "properties.enableRbacAuthorization").Bool())

	// Optional+Computed: use r.Exists() pattern with absent-null branch.
	if r := gjson.Get(resp, "name"); r.Exists() {
		state.Name = types.StringValue(r.String())
	} else {
		state.Name = types.StringNull()
	}

	// subscription_id: Required + Immutable — preserve user casing via EqualFold.
	if apiVal := gjson.Get(resp, "subscription_id").String(); !strings.EqualFold(apiVal, state.SubscriptionID.ValueString()) {
		state.SubscriptionID = types.StringValue(apiVal)
	}

	// tags — Computed-only: empty map when absent/null (never MapNull).
	{
		tagMap := make(map[string]string)
		if r := gjson.Get(resp, "tags"); r.Exists() && r.Type != gjson.Null {
			r.ForEach(func(k, v gjson.Result) bool {
				tagMap[k.String()] = v.String()
				return true
			})
		}
		mv, d := types.MapValueFrom(ctx, types.StringType, tagMap)
		diags.Append(d...)
		state.Tags = mv
	}

	// labels — same pattern as tags.
	{
		labelMap := make(map[string]string)
		if r := gjson.Get(resp, "labels"); r.Exists() && r.Type != gjson.Null {
			r.ForEach(func(k, v gjson.Result) bool {
				labelMap[k.String()] = v.String()
				return true
			})
		}
		mv, d := types.MapValueFrom(ctx, types.StringType, labelMap)
		diags.Append(d...)
		state.Labels = mv
	}

	// sku — Computed-only SingleNestedAttribute, always populated.
	state.Sku = AzureSkuTFSDK{
		Family: types.StringValue(gjson.Get(resp, "properties.sku.family").String()),
		Name:   types.StringValue(gjson.Get(resp, "properties.sku.name").String()),
	}

	// acls — Optional+Computed; SetAclsStateFromJSON always writes empty or populated Set.
	setAzureVaultAclsFromJSON(ctx, gjson.Get(resp, "acls"), &state.Acls, diags)
}

// setAzureVaultAclsFromJSON hydrates the Acls Set from a gjson result.
// Absent, null, or empty acls produce an empty Set (not null), so "acls.%" count checks work.
func setAzureVaultAclsFromJSON(ctx context.Context, r gjson.Result, dest *types.Set, diags *diag.Diagnostics) {
	var objs []attr.Value
	if r.Exists() && r.Type != gjson.Null {
		r.ForEach(func(_, v gjson.Result) bool {
			var allowVals []attr.Value
			v.Get("allow_list").ForEach(func(_, op gjson.Result) bool {
				allowVals = append(allowVals, types.StringValue(op.String()))
				return true
			})
			if allowVals == nil {
				allowVals = []attr.Value{}
			}
			allowList, d := types.ListValue(types.StringType, allowVals)
			diags.Append(d...)
			obj, d := types.ObjectValue(azureVaultAclAttrTypes, map[string]attr.Value{
				"group":      types.StringValue(v.Get("group").String()),
				"allow_list": allowList,
			})
			diags.Append(d...)
			objs = append(objs, obj)
			return true
		})
	}
	if objs == nil {
		objs = []attr.Value{}
	}
	sv, d := types.SetValue(azureVaultAclElemType, objs)
	diags.Append(d...)
	*dest = sv
}

// hydrateAzureVaultDataSourceState populates a data source state struct from an API response.
func hydrateAzureVaultDataSourceState(ctx context.Context, resp string, state *AzureVaultDataSourceTFSDK, diags *diag.Diagnostics) {
	state.ID             = types.StringValue(gjson.Get(resp, "id").String())
	state.URI            = types.StringValue(gjson.Get(resp, "uri").String())
	state.ConnectionName = types.StringValue(gjson.Get(resp, "connection").String())
	state.AzureVaultID   = types.StringValue(gjson.Get(resp, "azure_vault_id").String())
	state.AzureName      = types.StringValue(gjson.Get(resp, "azure_name").String())
	state.CloudName      = types.StringValue(gjson.Get(resp, "cloud_name").String())
	state.Location       = types.StringValue(gjson.Get(resp, "location").String())
	state.Type           = types.StringValue(gjson.Get(resp, "type").String())
	state.SubscriptionID = types.StringValue(gjson.Get(resp, "subscription_id").String())
	state.SubscriptionName        = types.StringValue(gjson.Get(resp, "subscription_name").String())
	state.Account        = types.StringValue(gjson.Get(resp, "account").String())
	state.Application    = types.StringValue(gjson.Get(resp, "application").String())
	state.DevAccount     = types.StringValue(gjson.Get(resp, "devAccount").String())
	state.CreatedAt      = types.StringValue(gjson.Get(resp, "createdAt").String())
	state.UpdatedAt      = types.StringValue(gjson.Get(resp, "updatedAt").String())
	state.TenantID       = types.StringValue(gjson.Get(resp, "properties.tenantId").String())
	state.VaultURI       = types.StringValue(gjson.Get(resp, "properties.vaultUri").String())
	state.CreateMode     = types.StringValue(gjson.Get(resp, "properties.createMode").String())
	state.EnabledForDeployment         = types.BoolValue(gjson.Get(resp, "properties.enabledForDeployment").Bool())
	state.EnabledForDiskEncryption     = types.BoolValue(gjson.Get(resp, "properties.enabledForDiskEncryption").Bool())
	state.EnabledForTemplateDeployment = types.BoolValue(gjson.Get(resp, "properties.enabledForTemplateDeployment").Bool())
	state.EnableSoftDelete             = types.BoolValue(gjson.Get(resp, "properties.enableSoftDelete").Bool())
	state.EnablePurgeProtection        = types.BoolValue(gjson.Get(resp, "properties.enablePurgeProtection").Bool())
	state.SoftDeleteRetentionInDays    = types.Int64Value(gjson.Get(resp, "properties.softDeleteRetentionInDays").Int())
	state.EnableRbacAuthorization      = types.BoolValue(gjson.Get(resp, "properties.enableRbacAuthorization").Bool())
	state.CloudKeyBackupLimit          = types.Int64Value(gjson.Get(resp, "cloud_key_backup_limit").Int())
	state.Sku = AzureSkuTFSDK{
		Family: types.StringValue(gjson.Get(resp, "properties.sku.family").String()),
		Name:   types.StringValue(gjson.Get(resp, "properties.sku.name").String()),
	}

	if r := gjson.Get(resp, "name"); r.Exists() {
		state.Name = types.StringValue(r.String())
	} else {
		state.Name = types.StringNull()
	}

	{
		tagMap := make(map[string]string)
		if r := gjson.Get(resp, "tags"); r.Exists() && r.Type != gjson.Null {
			r.ForEach(func(k, v gjson.Result) bool { tagMap[k.String()] = v.String(); return true })
		}
		mv, d := types.MapValueFrom(ctx, types.StringType, tagMap)
		diags.Append(d...)
		state.Tags = mv
	}

	{
		labelMap := make(map[string]string)
		if r := gjson.Get(resp, "labels"); r.Exists() && r.Type != gjson.Null {
			r.ForEach(func(k, v gjson.Result) bool { labelMap[k.String()] = v.String(); return true })
		}
		mv, d := types.MapValueFrom(ctx, types.StringType, labelMap)
		diags.Append(d...)
		state.Labels = mv
	}
}
