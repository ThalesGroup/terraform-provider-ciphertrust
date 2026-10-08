package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const azureVaultListFiltersTable = "\n\n> **Note:** Although some filters represent integers, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"-1\"` rather than `-1`.\n\n" +
	"| filter            | type    | description |\n" +
	"|-------------------|---------|-------------|\n" +
	"| skip              | integer | Index of the first result to return (default: 0). |\n" +
	"| limit             | integer | Maximum number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort              | string  | Fields to sort by. Valid sort fields are `azure_name`, `updatedAt`, and `createdAt`. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| id                | string  | Filter by CipherTrust Manager resource ID. |\n" +
	"| name              | string  | Filter by CipherTrust Manager resource name (`azure_name::subscription_id` format). |\n" +
	"| location          | string  | Filter by Azure region. |\n" +
	"| cloud_name        | string  | Filter by cloud name (for example, `AzureCloud`). |\n" +
	"| subscription_id   | string  | Filter by Azure subscription ID. |\n" +
	"| subscription_name | string  | Filter by subscription display name. |\n" +
	"| job_config_id     | string  | Filter by CipherTrust Manager scheduler job configuration ID. |\n" +
	"| type              | string  | Filter by vault type. Use `vault` for Key Vaults and `managedHsm` for Managed HSM vaults. |"

var (
	_ datasource.DataSource                     = &dataSourceAzureVaultList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureVaultList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureVaultList{}

	azureVaultListValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"id": {}, "name": {}, "location": {}, "cloud_name": {},
		"subscription_id": {}, "subscription_name": {}, "job_config_id": {}, "type": {},
	}
)

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureVaultList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureVaultListFilterValidator{}}
}

type azureVaultListFilterValidator struct{}

func (v azureVaultListFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}
func (v azureVaultListFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v azureVaultListFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureVaultListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	for k := range config.Filters.Elements() {
		if _, ok := azureVaultListValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key for ciphertrust_azure_vault_list.", k),
			)
		}
	}
}

// NewDataSourceAzureVaultList returns a new instance of the
// ciphertrust_azure_vault_list data source.
func NewDataSourceAzureVaultList() datasource.DataSource {
	return &dataSourceAzureVaultList{}
}

type dataSourceAzureVaultList struct {
	client *common.Client
}

func (d *dataSourceAzureVaultList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_vault_list"
}

func (d *dataSourceAzureVaultList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *dataSourceAzureVaultList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of Azure Key Vaults added to the " +
			"CipherTrust Manager database. Supply a `filters` map to narrow results.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure vaults." + azureVaultListFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of vaults matching the given filters.",
			},
			"vaults": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of Azure vaults added to CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the vault.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Azure name of the vault.",
						},
						"azure_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource ID of the vault.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud name as returned by CipherTrust Manager.",
						},
						"connection": schema.StringAttribute{
							Computed:    true,
							Description: "Azure connection identifier as stored in CipherTrust Manager.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the vault was added to CipherTrust Manager.",
						},
						"location": schema.StringAttribute{
							Computed:    true,
							Description: "Azure region where the vault is located.",
						},
						"subscription_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure subscription ID that contains the vault.",
						},
						"subscription_name": schema.StringAttribute{
							Computed:    true,
							Description: "Display name of the Azure subscription.",
						},
						"synced_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the vault was last synced.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the vault was last updated in CipherTrust Manager.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager unique identifier URI for the vault.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource type of the vault.",
						},
						"tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Azure tags applied to the vault.",
						},
						"vault_properties": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Azure vault properties.",
							Attributes: map[string]schema.Attribute{
								"tenant_id": schema.StringAttribute{
									Computed:    true,
									Description: "Azure Active Directory tenant ID for the vault.",
								},
								"vault_uri": schema.StringAttribute{
									Computed:    true,
									Description: "URI for performing operations on keys and secrets in this vault.",
								},
								"enabled_for_deployment": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Virtual Machines may retrieve certificates stored as secrets.",
								},
								"enabled_for_disk_encryption": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Disk Encryption may retrieve secrets from the vault.",
								},
								"enabled_for_template_deployment": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Resource Manager may retrieve secrets from the vault.",
								},
								"enable_soft_delete": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether soft delete is enabled for the vault.",
								},
								"create_mode": schema.StringAttribute{
									Computed:    true,
									Description: "Vault create mode.",
								},
								"enable_purge_protection": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether protection against purge is enabled.",
								},
								"soft_delete_retention_in_days": schema.Int64Attribute{
									Computed:    true,
									Description: "Soft delete data retention period in days.",
								},
								"enable_rbac_authorization": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether RBAC is used for data action authorization.",
								},
								"sku": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "SKU details for the vault.",
									Attributes: map[string]schema.Attribute{
										"family": schema.StringAttribute{
											Computed:    true,
											Description: "SKU family name.",
										},
										"name": schema.StringAttribute{
											Computed:    true,
											Description: "SKU name.",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read lists Azure vaults from the CipherTrust Manager database, optionally
// filtered by the key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceAzureVaultList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_vault_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_vault_list.go -> Read][" + id + "]")

	var state models.AzureVaultListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if val, ok := v.(types.String); ok {
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AZURE+"/vaults", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_vault_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read Azure vaults from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var page models.AzureVaultListPageJSON
	if err = json.Unmarshal([]byte(jsonStr), &page); err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_vault_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read Azure vaults from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	state.Vaults = []models.AzureVaultListEntryTFSDK{}
	for _, v := range page.Resources {
		entry := azureVaultListEntryToTFSDK(ctx, v, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Vaults = append(state.Vaults, entry)
	}
	state.Matched = types.Int64Value(page.Total)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// azureVaultListEntryToTFSDK converts one AzureVaultListEntryJSON to its TFSDK equivalent.
func azureVaultListEntryToTFSDK(ctx context.Context, v models.AzureVaultListEntryJSON, diags *diag.Diagnostics) models.AzureVaultListEntryTFSDK {
	entry := models.AzureVaultListEntryTFSDK{
		ID:               types.StringValue(v.ID),
		Name:             types.StringValue(v.AzureName),
		AzureVaultID:     types.StringValue(v.AzureVaultID),
		CloudName:        types.StringValue(v.CloudName),
		Connection:       types.StringValue(v.Connection),
		CreatedAt:        types.StringValue(v.CreatedAt),
		Location:         types.StringValue(v.Location),
		SubscriptionID:   types.StringValue(v.SubscriptionID),
		SubscriptionName: types.StringValue(v.SubscriptionName),
		SyncedAt:         types.StringValue(v.SyncedAt),
		UpdatedAt:        types.StringValue(v.UpdatedAt),
		URI:              types.StringValue(v.URI),
		VaultType:        types.StringValue(v.VaultType),
	}

	// tags: null when absent or empty.
	if len(v.Tags) > 0 {
		tv, d := types.MapValueFrom(ctx, types.StringType, v.Tags)
		diags.Append(d...)
		if diags.HasError() {
			return entry
		}
		entry.Tags = tv
	} else {
		entry.Tags = types.MapNull(types.StringType)
	}

	// vault_properties: reuse the same attr types as the resource.
	skuAttrTypes := map[string]attr.Type{
		"family": types.StringType,
		"name":   types.StringType,
	}
	skuObj, d := types.ObjectValue(skuAttrTypes, map[string]attr.Value{
		"family": types.StringValue(v.Properties.Sku.Family),
		"name":   types.StringValue(v.Properties.Sku.Name),
	})
	diags.Append(d...)
	if diags.HasError() {
		return entry
	}
	vpObj, d := types.ObjectValue(vaultPropertiesAttrTypes(), map[string]attr.Value{
		"tenant_id":                       types.StringValue(v.Properties.TenantID),
		"sku":                             skuObj,
		"vault_uri":                       types.StringValue(v.Properties.VaultURI),
		"enabled_for_deployment":          types.BoolValue(v.Properties.EnabledForDeployment),
		"enabled_for_disk_encryption":     types.BoolValue(v.Properties.EnabledForDiskEncryption),
		"enabled_for_template_deployment": types.BoolValue(v.Properties.EnabledForTemplateDeployment),
		"enable_soft_delete":              types.BoolValue(v.Properties.EnableSoftDelete),
		"create_mode":                     types.StringValue(v.Properties.CreateMode),
		"enable_purge_protection":         types.BoolValue(v.Properties.EnablePurgeProtection),
		"soft_delete_retention_in_days":   types.Int64Value(int64(v.Properties.SoftDeleteRetentionInDays)),
		"enable_rbac_authorization":       types.BoolValue(v.Properties.EnableRbacAuthorization),
	})
	diags.Append(d...)
	entry.VaultProperties = vpObj
	return entry
}
