package azure

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAzureVaultsList{}
	_ datasource.DataSourceWithConfigure = &dataSourceAzureVaultsList{}
)

// NewDataSourceAzureVaultsList returns a new ciphertrust_azure_vaults data source.
func NewDataSourceAzureVaultsList() datasource.DataSource {
	return &dataSourceAzureVaultsList{}
}

type dataSourceAzureVaultsList struct {
	client *common.Client
}

func (d *dataSourceAzureVaultsList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_vaults"
}

func (d *dataSourceAzureVaultsList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *dataSourceAzureVaultsList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to list Azure vaults registered in CipherTrust Manager CCKM.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by vault name.",
			},
			"subscription_id": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by Azure subscription ID.",
			},
			"connection_name": schema.StringAttribute{
				Optional:    true,
				Description: "Filter by Azure connection name.",
			},
			"resources": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of Azure vaults matching the filter criteria.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "URI of the vault in CipherTrust Manager.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the vault.",
						},
						"connection_name": schema.StringAttribute{
							Computed:    true,
							Description: "Azure connection name.",
						},
						"azure_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource ID of the vault.",
						},
						"azure_name": schema.StringAttribute{
							Computed:    true,
							Description: "Azure name of the vault.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud name (e.g. AzureCloud).",
						},
						"location": schema.StringAttribute{
							Computed:    true,
							Description: "Azure region where the vault is located.",
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource type.",
						},
						"subscription_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure subscription ID.",
						},
						"subscription_name": schema.StringAttribute{
							Computed:    true,
							Description: "Azure subscription name.",
						},
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust account URI.",
						},
						"application": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust application URI.",
						},
						"dev_account": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust dev account URI.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the vault was registered in CM.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Timestamp when the vault record was last updated.",
						},
						"tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Azure resource tags.",
						},
						"labels": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "CipherTrust labels.",
						},
						"tenant_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure tenant ID from vault properties.",
						},
						"vault_uri": schema.StringAttribute{
							Computed:    true,
							Description: "Vault URI from Azure properties.",
						},
						"enabled_for_deployment": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether vault is enabled for deployment.",
						},
						"enabled_for_disk_encryption": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether vault is enabled for disk encryption.",
						},
						"enabled_for_template_deployment": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether vault is enabled for template deployment.",
						},
						"enable_soft_delete": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether soft delete is enabled.",
						},
						"create_mode": schema.StringAttribute{
							Computed:    true,
							Description: "Vault create mode from Azure properties.",
						},
						"enable_purge_protection": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether purge protection is enabled.",
						},
						"soft_delete_retention_in_days": schema.Int64Attribute{
							Computed:    true,
							Description: "Soft delete retention period in days.",
						},
						"enable_rbac_authorization": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether RBAC authorization is enabled.",
						},
						"sku": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "SKU details of the vault.",
							Attributes: map[string]schema.Attribute{
								"family": schema.StringAttribute{Computed: true},
								"name":   schema.StringAttribute{Computed: true},
							},
						},
						"cloud_key_backup_limit": schema.Int64Attribute{
							Computed:    true,
							Description: "Cloud key backup limit.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceAzureVaultsList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state AzureVaultsListDataSourceTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	if !state.Name.IsNull() {
		filters.Set("name", state.Name.ValueString())
	}
	if !state.SubscriptionID.IsNull() {
		filters.Set("subscription_id", state.SubscriptionID.ValueString())
	}
	if !state.ConnectionName.IsNull() {
		// CM API uses "connection" as the query parameter key.
		filters.Set("connection", state.ConnectionName.ValueString())
	}

	listResp, err := d.client.ListWithFilters(ctx, "", URL_AZURE_VAULTS, filters)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading CipherTrust Azure Vaults",
			"Could not list Azure vaults: "+err.Error())
		return
	}

	// Initialise to empty slice so resources.# = 0 on zero matches (not null).
	state.Resources = []AzureVaultDataSourceTFSDK{}
	gjson.Get(listResp, "resources").ForEach(func(_, v gjson.Result) bool {
		var item AzureVaultDataSourceTFSDK
		hydrateAzureVaultDataSourceState(ctx, v.Raw, &item, &resp.Diagnostics)
		state.Resources = append(state.Resources, item)
		return true
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
